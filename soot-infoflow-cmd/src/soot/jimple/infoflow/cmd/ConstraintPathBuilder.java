package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Builds and validates constraint paths by combining inter-method call graph
 * traversal
 * with intra-method constraint extraction. Coordinates the overall path
 * construction process.
 */
public class ConstraintPathBuilder {
    private final AllocationGraphAnalyzer graphAnalyzer;
    private final ConstraintExtractor constraintExtractor;
    private final Map<SootMethod, Set<SootMethod>> methodToCallers;
    private final Map<SootMethod, List<ConstraintPath>> methodToPaths;
    private final Set<SootMethod> processedMethods;
    private final int maxPathDepth;
    private final boolean enablePathMerging;

    public ConstraintPathBuilder(AllocationGraphAnalyzer graphAnalyzer, ConstraintExtractor constraintExtractor) {
        this.graphAnalyzer = graphAnalyzer;
        this.constraintExtractor = constraintExtractor;
        this.methodToCallers = new ConcurrentHashMap<>();
        this.methodToPaths = new ConcurrentHashMap<>();
        this.processedMethods = ConcurrentHashMap.newKeySet();
        this.maxPathDepth = 50; // Prevent infinite recursion
        this.enablePathMerging = true;

        // Pre-build caller map for efficiency
        // buildCallerMap();
    }

    /**
     * Build all constraint paths leading to the target method
     */
    public List<ConstraintPath> buildPathsToTarget(SootMethod targetMethod) {
        System.out.println("Building constraint paths to: " + targetMethod.getSignature());

        List<ConstraintPath> allPaths = new ArrayList<>();
        Set<SootMethod> visitedMethods = new HashSet<>();

        // Start backward traversal from target method
        buildPathsRecursive(targetMethod, new ArrayList<>(), new ArrayList<>(),
                allPaths, visitedMethods, 0);

        // Post-process paths
        if (enablePathMerging) {
            allPaths = mergeCompatiblePaths(allPaths);
        }

        // Sort by validity and constraint count
        allPaths.sort((p1, p2) -> {
            if (p1.isValidPath() != p2.isValidPath()) {
                return p1.isValidPath() ? -1 : 1;
            }
            return Integer.compare(p1.getConstraintCount(), p2.getConstraintCount());
        });

        System.out.println("Found " + allPaths.size() + " constraint paths");
        return allPaths;
    }

    /**
     * Recursive method to build paths backward from target
     */
    private void buildPathsRecursive(SootMethod currentMethod, List<SootMethod> methodPath,
            List<Constraint> pathConstraints, List<ConstraintPath> allPaths,
            Set<SootMethod> visitedInPath, int depth) {

        System.out.println("DEBUG: buildPathsRecursive depth=" + depth +
                ", current=" + currentMethod.getName() +
                ", pathLength=" + methodPath.size());

        // Prevent infinite recursion and cycles
        if (depth > maxPathDepth || visitedInPath.contains(currentMethod)) {
            System.out.println("  Stopping: depth limit or cycle detected");
            return;
        }

        visitedInPath.add(currentMethod);
        methodPath.add(0, currentMethod); // Add to beginning (backward path)

        // Get all callers of current method
        Set<SootMethod> callers = findAllCallers(currentMethod);

        if (callers.isEmpty()) {
            // Reached entry point - create complete path
            System.out.println("  ENTRY POINT REACHED - Creating path with " + methodPath.size() + " methods");
            System.out.println("  Path sequence: " +
                    methodPath.stream().map(SootMethod::getName).collect(Collectors.joining(" -> ")));
            createCompletePath(methodPath, pathConstraints, allPaths);
        } else {
            System.out.println("  Found " + callers.size() + " callers, continuing recursion...");

            // Continue backward traversal through each caller
            for (SootMethod caller : callers) {
                System.out.println("  Processing caller: " + caller.getName());

                // Extract constraints from caller to current method
                List<Constraint> callerConstraints = extractConstraintsInMethod(caller, currentMethod);
                System.out.println("    Extracted " + callerConstraints.size() + " constraints");

                // Combine with existing path constraints
                List<Constraint> newPathConstraints = new ArrayList<>(pathConstraints);
                newPathConstraints.addAll(0, callerConstraints); // Add to beginning

                // Recursive call
                buildPathsRecursive(caller, new ArrayList<>(methodPath), newPathConstraints,
                        allPaths, new HashSet<>(visitedInPath), depth + 1);
            }
        }

        visitedInPath.remove(currentMethod);
    }

    /**
     * Find all methods that call the target method (hybrid approach) with detailed
     * logging
     */
    private Set<SootMethod> findAllCallers(SootMethod targetMethod) {
        System.out.println("\n=== DEBUG: Finding Callers for " + targetMethod.getName() + " ===");

        Set<SootMethod> callGraphCallers = new HashSet<>();
        Set<SootMethod> allocationGraphCallers = new HashSet<>();

        // Method 1: Use call graph edges
        CallGraph callGraph = graphAnalyzer.getCallGraph();
        if (callGraph != null) {
            System.out.println("Scanning CallGraph for callers...");
            Iterator<Edge> incomingEdges = callGraph.edgesInto(targetMethod);
            while (incomingEdges.hasNext()) {
                Edge edge = incomingEdges.next();
                SootMethod caller = edge.src();
                if (caller != null) {
                    callGraphCallers.add(caller);
                    System.out.println("  CallGraph found: " + caller.getSignature());
                }
            }
            System.out.println("CallGraph total: " + callGraphCallers.size() + " callers");
        } else {
            System.out.println("CallGraph is null!");
        }

        // Method 2: Scan allocation graphs for METHOD_CALL nodes (supplementary)
        System.out.println("Scanning AllocationGraphs for callers...");
        Map<SootMethod, AllocationGraph> methodGraphs = graphAnalyzer.getMethodGraphs();
        int scannedGraphs = 0;
        for (Map.Entry<SootMethod, AllocationGraph> entry : methodGraphs.entrySet()) {
            SootMethod method = entry.getKey();
            AllocationGraph graph = entry.getValue();
            scannedGraphs++;

            // Check if this method calls our target
            if (methodCallsTarget(graph, targetMethod)) {
                allocationGraphCallers.add(method);
                System.out.println("  AllocationGraph found: " + method.getSignature());
            }
        }
        System.out.println("AllocationGraph scanned " + scannedGraphs + " graphs, found: "
                + allocationGraphCallers.size() + " callers");

        // Combine results
        Set<SootMethod> allCallers = new HashSet<>();
        allCallers.addAll(callGraphCallers);
        allCallers.addAll(allocationGraphCallers);

        // Print analysis
        Set<SootMethod> onlyInCallGraph = new HashSet<>(callGraphCallers);
        onlyInCallGraph.removeAll(allocationGraphCallers);

        Set<SootMethod> onlyInAllocationGraph = new HashSet<>(allocationGraphCallers);
        onlyInAllocationGraph.removeAll(callGraphCallers);

        Set<SootMethod> inBoth = new HashSet<>(callGraphCallers);
        inBoth.retainAll(allocationGraphCallers);

        System.out.println("\n--- Caller Discovery Analysis ---");
        System.out.println("Total unique callers: " + allCallers.size());
        System.out.println("Only in CallGraph: " + onlyInCallGraph.size());
        System.out.println("Only in AllocationGraph: " + onlyInAllocationGraph.size());
        System.out.println("In both: " + inBoth.size());

        if (!onlyInCallGraph.isEmpty()) {
            System.out.println("CallGraph-only callers:");
            onlyInCallGraph.forEach(m -> System.out.println("  " + m.getName()));
        }

        if (!onlyInAllocationGraph.isEmpty()) {
            System.out.println("AllocationGraph-only callers:");
            onlyInAllocationGraph.forEach(m -> System.out.println("  " + m.getName()));
        }

        System.out.println("=== END DEBUG ===\n");

        return allCallers;
    }

    /**
     * Check if an allocation graph contains calls to target method (with debug
     * logging)
     */
    private boolean methodCallsTarget(AllocationGraph graph, SootMethod targetMethod) {
        Set<AllocationNode> allNodes = graph.getNodes();
        boolean foundCall = false;

        for (AllocationNode node : allNodes) {
            if (node.getType() == NodeType.METHOD_CALL) {
                InvokeExpr invoke = node.getMethodCall();
                if (invoke != null && invoke.getMethod().equals(targetMethod)) {
                    foundCall = true;
                    // Debug: print the calling context
                    System.out.println("    METHOD_CALL found in " + graph.getMethod().getName() +
                            " at unit: " + (node.getUnit() != null ? node.getUnit().toString() : "null"));
                    break; // Found one, that's enough
                }
            }
        }

        return foundCall;
    }

    /**
     * Extract constraints within a method that lead to calling the target method
     */
    private List<Constraint> extractConstraintsInMethod(SootMethod callerMethod, SootMethod targetMethod) {
        List<Constraint> constraints = new ArrayList<>();

        // Get caller's allocation graph
        AllocationGraph callerGraph = graphAnalyzer.getMethodGraphs().get(callerMethod);
        if (callerGraph == null) {
            return constraints;
        }

        // Find METHOD_CALL nodes that invoke target method
        List<AllocationNode> targetCallNodes = findTargetCallNodes(callerGraph, targetMethod);

        for (AllocationNode callNode : targetCallNodes) {
            // Extract constraints from this specific call path
            List<Constraint> callConstraints = extractConstraintsForCall(callerGraph, callNode);
            constraints.addAll(callConstraints);
        }

        return constraints;
    }

    /**
     * Find all nodes in the graph that call the target method
     */
    private List<AllocationNode> findTargetCallNodes(AllocationGraph graph, SootMethod targetMethod) {
        List<AllocationNode> callNodes = new ArrayList<>();

        for (AllocationNode node : graph.getNodes()) {
            if (node.getType() == NodeType.METHOD_CALL) {
                InvokeExpr invoke = node.getMethodCall();
                if (invoke != null && invoke.getMethod().equals(targetMethod)) {
                    callNodes.add(node);
                }
            }
        }

        return callNodes;
    }

    /**
     * Extract constraints that lead to a specific method call
     */
    private List<Constraint> extractConstraintsForCall(AllocationGraph graph, AllocationNode targetCallNode) {
        List<Constraint> constraints = new ArrayList<>();
        Set<AllocationNode> visited = new HashSet<>();

        // Trace backwards from call node to find constraining conditions
        traceBackwardForConstraints(graph, targetCallNode, constraints, visited);

        return constraints;
    }

    /**
     * Trace backward through graph to find constraining nodes
     */
    private void traceBackwardForConstraints(AllocationGraph graph, AllocationNode currentNode,
            List<Constraint> constraints, Set<AllocationNode> visited) {

        if (visited.contains(currentNode)) {
            return;
        }
        visited.add(currentNode);

        // Process current node if it's a constraint node
        if (currentNode.getType() == NodeType.IF_CONDITION) {
            // Determine which branch leads to our target
            boolean takeTrueBranch = determineBranchDirection(graph, currentNode, visited);

            try {
                ConditionalConstraint constraint = constraintExtractor.extractConditionalConstraint(
                        currentNode, takeTrueBranch);
                constraints.add(constraint);
            } catch (Exception e) {
                System.err.println("Error extracting conditional constraint: " + e.getMessage());
            }

        } else if (currentNode.getType() == NodeType.SWITCH) {
            // Determine which case leads to our target
            String caseValue = determineSwitchCase(graph, currentNode, visited);

            try {
                SwitchConstraint constraint = constraintExtractor.extractSwitchConstraint(
                        currentNode, caseValue, "default".equals(caseValue));
                constraints.add(constraint);
            } catch (Exception e) {
                System.err.println("Error extracting switch constraint: " + e.getMessage());
            }
        }

        // Continue tracing backward through predecessors
        for (AllocationNode predecessor : currentNode.getPredecessors()) {
            traceBackwardForConstraints(graph, predecessor, constraints, visited);
        }
    }

    /**
     * Determine which branch of an IF condition leads to the target
     */
    private boolean determineBranchDirection(AllocationGraph graph, AllocationNode ifNode,
            Set<AllocationNode> targetPath) {
        // Use BFS to see which successor path reaches our target
        Set<AllocationNode> successors = ifNode.getSuccessors();

        for (AllocationNode successor : successors) {
            if (pathReachesTarget(successor, targetPath, new HashSet<>())) {
                // This is the first successor, so it's the TRUE branch
                return successors.iterator().next().equals(successor);
            }
        }

        return true; // Default to true branch
    }

    /**
     * Check if a path from this node reaches any node in target path
     */
    private boolean pathReachesTarget(AllocationNode startNode, Set<AllocationNode> targetPath,
            Set<AllocationNode> visited) {
        if (visited.contains(startNode) || targetPath.contains(startNode)) {
            return targetPath.contains(startNode);
        }

        visited.add(startNode);

        for (AllocationNode successor : startNode.getSuccessors()) {
            if (pathReachesTarget(successor, targetPath, visited)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine which case of a switch statement leads to the target
     */
    private String determineSwitchCase(AllocationGraph graph, AllocationNode switchNode,
            Set<AllocationNode> targetPath) {
        // For now, return a placeholder - would need more sophisticated analysis
        // to determine the actual case value from the graph structure
        return "case_value";
    }

    /**
     * Create a complete constraint path from method sequence and constraints
     */
    private void createCompletePath(List<SootMethod> methodSequence, List<Constraint> constraints,
            List<ConstraintPath> allPaths) {

        if (methodSequence.isEmpty()) {
            return;
        }

        SootMethod entryPoint = methodSequence.get(0);
        SootMethod targetMethod = methodSequence.get(methodSequence.size() - 1);

        // Determine path type based on entry point
        PathType pathType = determinePathType(entryPoint);

        String pathId = "path_" + System.nanoTime();
        ConstraintPath path = new ConstraintPath(pathId, targetMethod, entryPoint, pathType);

        // Add methods to sequence
        for (int i = 1; i < methodSequence.size(); i++) {
            path.addMethodToSequence(methodSequence.get(i));
        }

        // Add constraints
        path.addConstraints(constraints);

        // Add metadata
        path.addMetadata("depth", methodSequence.size());
        path.addMetadata("constraint_count", constraints.size());

        allPaths.add(path);
    }

    /**
     * Determine path type based on entry point
     */
    private PathType determinePathType(SootMethod entryPoint) {
        String className = entryPoint.getDeclaringClass().getName();
        String methodName = entryPoint.getName();

        if (methodName.contains("onCreate") || methodName.contains("onStart") || methodName.contains("onResume")) {
            return PathType.ACTIVITY_LIFECYCLE;
        } else if (className.contains("Service")) {
            return PathType.SERVICE_LIFECYCLE;
        } else if (className.contains("Receiver")) {
            return PathType.BROADCAST_RECEIVER;
        } else if (className.contains("Provider")) {
            return PathType.CONTENT_PROVIDER;
        } else if (methodName.contains("onClick") || methodName.contains("onTouch")) {
            return PathType.USER_INTERACTION;
        } else if (methodName.contains("run") || className.contains("Thread")) {
            return PathType.THREAD_EXECUTION;
        } else {
            return PathType.OTHER;
        }
    }

    /**
     * Merge compatible paths to reduce redundancy
     */
    private List<ConstraintPath> mergeCompatiblePaths(List<ConstraintPath> paths) {
        List<ConstraintPath> mergedPaths = new ArrayList<>();
        Set<ConstraintPath> processed = new HashSet<>();

        for (ConstraintPath path : paths) {
            if (processed.contains(path)) {
                continue;
            }

            List<ConstraintPath> compatiblePaths = findCompatiblePaths(path, paths);

            if (compatiblePaths.size() > 1) {
                // Merge compatible paths
                ConstraintPath mergedPath = mergePathGroup(compatiblePaths);
                mergedPaths.add(mergedPath);
                processed.addAll(compatiblePaths);
            } else {
                mergedPaths.add(path);
                processed.add(path);
            }
        }

        return mergedPaths;
    }

    /**
     * Find paths that can be merged with the given path
     */
    private List<ConstraintPath> findCompatiblePaths(ConstraintPath basePath, List<ConstraintPath> allPaths) {
        List<ConstraintPath> compatible = new ArrayList<>();
        compatible.add(basePath);

        for (ConstraintPath otherPath : allPaths) {
            if (otherPath.equals(basePath)) {
                continue;
            }

            // Check if paths are compatible for merging
            if (arePathsCompatible(basePath, otherPath)) {
                compatible.add(otherPath);
            }
        }

        return compatible;
    }

    /**
     * Check if two paths can be merged
     */
    private boolean arePathsCompatible(ConstraintPath path1, ConstraintPath path2) {
        // Same target method
        if (!path1.getTargetMethod().equals(path2.getTargetMethod())) {
            return false;
        }

        // Same entry point
        if (!path1.getEntryPoint().equals(path2.getEntryPoint())) {
            return false;
        }

        // Compatible constraints
        for (Constraint c1 : path1.getConstraints()) {
            for (Constraint c2 : path2.getConstraints()) {
                if (!c1.isCompatibleWith(c2)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Merge a group of compatible paths
     */
    private ConstraintPath mergePathGroup(List<ConstraintPath> paths) {
        if (paths.isEmpty()) {
            throw new IllegalArgumentException("Cannot merge empty path group");
        }

        ConstraintPath result = paths.get(0).copy();

        for (int i = 1; i < paths.size(); i++) {
            result = result.mergeWith(paths.get(i));
        }

        return result;
    }

    /**
     * Build caller map for efficient lookup
     */
    private void buildCallerMap() {
        CallGraph callGraph = graphAnalyzer.getCallGraph();
        if (callGraph == null) {
            System.err.println("Warning: CallGraph is null, skipping caller map building");
            return;
        }

        System.out.println("Building caller map from call graph...");

        for (Edge edge : callGraph) {
            SootMethod caller = edge.src();
            SootMethod callee = edge.tgt();

            // Skip phantom/null methods
            if (caller == null || callee == null) {
                continue;
            }

            methodToCallers.computeIfAbsent(callee, k -> ConcurrentHashMap.newKeySet()).add(caller);
        }

        System.out.println("Caller map built with " + methodToCallers.size() + " methods");
    }

    private void ensureCallerMapBuilt() {
        CallGraph callGraph = graphAnalyzer.getCallGraph();
        if (methodToCallers.isEmpty() && callGraph != null) {
            buildCallerMap();
        }
    }

    /**
     * Get entry points for the analysis
     */
    public Set<SootMethod> getEntryPoints() {
        Set<SootMethod> entryPoints = new HashSet<>();

        // Add component entry points
        Map<String, Set<SootClass>> componentClasses = graphAnalyzer.getComponentTypeToClasses();
        Map<SootClass, Set<SootMethod>> componentMethods = graphAnalyzer.getComponentToMethods();

        for (Set<SootClass> classes : componentClasses.values()) {
            for (SootClass clazz : classes) {
                Set<SootMethod> methods = componentMethods.get(clazz);
                if (methods != null) {
                    entryPoints.addAll(methods);
                }
            }
        }

        // Add dummy main if available
        SootMethod dummyMain = graphAnalyzer.getDummyMainMethod();
        if (dummyMain != null) {
            entryPoints.add(dummyMain);
        }

        return entryPoints;
    }

    /**
     * Cleanup resources
     */
    public void cleanup() {
        constraintExtractor.shutdown();
    }

    // Getters for debugging and analysis
    public Map<SootMethod, Set<SootMethod>> getMethodToCallers() {
        return Collections.unmodifiableMap(methodToCallers);
    }

    public Map<SootMethod, List<ConstraintPath>> getMethodToPaths() {
        return Collections.unmodifiableMap(methodToPaths);
    }

}