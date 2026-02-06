package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Builds constraint paths by traversing AllocationGraph backward from target
 * methods.
 * Uses step-by-step targeting approach where each condition is analyzed with
 * its immediate target.
 * Now includes comprehensive debug logging and LLM interaction tracking.
 */
public class ConstraintPathBuilder {
    private final AllocationGraphAnalyzer graphAnalyzer;
    private final ConstraintExtractor constraintExtractor;
    private final Map<SootMethod, Set<SootMethod>> methodToCallers;
    private final int maxPathDepth;
    private final LLMInteractionLogger interactionLogger;

    public ConstraintPathBuilder(AllocationGraphAnalyzer graphAnalyzer, ConstraintExtractor constraintExtractor) {
        this(graphAnalyzer, constraintExtractor, null);
    }

    public ConstraintPathBuilder(AllocationGraphAnalyzer graphAnalyzer, ConstraintExtractor constraintExtractor,
            LLMInteractionLogger interactionLogger) {
        this.graphAnalyzer = graphAnalyzer;
        this.constraintExtractor = constraintExtractor;
        this.interactionLogger = interactionLogger;
        this.methodToCallers = new ConcurrentHashMap<>();
        this.maxPathDepth = 50;
    }

    /**
     * Build all constraint paths that lead to the target method
     */
    public List<ConstraintPath> buildPathsToTarget(SootMethod targetMethod) {
        System.out.println("\n=================================================================");
        System.out.println("               CONSTRAINT PATH BUILDER");
        System.out.println("=================================================================");
        System.out.println("Building constraint paths to: " + targetMethod.getSignature());

        List<ConstraintPath> allPaths = new ArrayList<>();
        Set<SootMethod> visitedMethods = new HashSet<>();

        // Start recursive path building
        buildPathsRecursive(targetMethod, new ArrayList<>(), new ArrayList<>(),
                allPaths, visitedMethods, 0);

        System.out.println("-----------------------------------------------------------------");
        System.out.println(" PATH BUILDING COMPLETE");
        System.out.println(" Found " + String.format("%-3d", allPaths.size()) + " constraint paths");
        System.out.println("-----------------------------------------------------------------");

        return allPaths;
    }

    /**
     * Recursively build paths by following caller relationships
     */
    private void buildPathsRecursive(SootMethod currentMethod, List<SootMethod> methodPath,
            List<Constraint> pathConstraints, List<ConstraintPath> allPaths,
            Set<SootMethod> visitedInPath, int depth) {

        System.out.println("\n>>> DEBUG: Recursive Path Building <<<");
        System.out.println("    Depth: " + depth + "/" + maxPathDepth);
        System.out.println("    Current Method: " + currentMethod.getName());
        System.out.println("    Path Length: " + methodPath.size() + " methods");
        System.out.println("    Constraints: " + pathConstraints.size());

        // Prevent infinite recursion and cycles
        if (depth > maxPathDepth || visitedInPath.contains(currentMethod)) {
            String reason = depth > maxPathDepth ? "depth limit reached" : "cycle detected";
            System.out.println("    WARNING: STOPPING - " + reason);
            return;
        }

        visitedInPath.add(currentMethod);
        methodPath.add(0, currentMethod); // Add to beginning (backward path)

        // === DEPTH-BASED CALLER LIMITING LOGIC ===
        int maxCallersToFind;
        if (depth == 1) {
            maxCallersToFind = 5;
        } else if (depth == 2) {
            maxCallersToFind = 3;
        } else {
            maxCallersToFind = 1;
        }

        System.out.println("    Caller limit for depth " + depth + ": " + maxCallersToFind);

        // Get limited callers of current method based on depth
        Set<SootMethod> callers = findCallersUsingCallGraph(currentMethod, maxCallersToFind);

        if (callers.isEmpty()) {
            // Reached entry point - create complete path
            System.out.println("    ENTRY POINT REACHED - Creating complete path");
            System.out.println("    Final method sequence (" + methodPath.size() + " methods):");
            for (int i = 0; i < methodPath.size(); i++) {
                System.out.println("      " + (i + 1) + ". " + methodPath.get(i).getName());
            }
            System.out.println("    Final constraints (" + pathConstraints.size() + "):");
            for (int i = 0; i < pathConstraints.size(); i++) {
                System.out.println("      " + (i + 1) + ". " + pathConstraints.get(i).getHumanReadableCondition());
            }

            createCompletePath(methodPath, pathConstraints, allPaths);
        } else {
            System.out.println("    Found " + callers.size()
                    + " callers (limited from potential larger set), continuing backward traversal:");

            // Continue backward traversal through each caller
            for (SootMethod caller : callers) {
                System.out.println("      Processing caller: " + caller.getName());

                // Extract constraints from caller to current method using step-by-step approach
                List<Constraint> callerConstraints = extractConstraintsForCaller(caller, currentMethod);
                System.out.println("         Extracted " + callerConstraints.size() + " constraints");

                // Log detailed constraint information
                if (!callerConstraints.isEmpty()) {
                    System.out.println("         Constraint details:");
                    for (Constraint constraint : callerConstraints) {
                        System.out.println("            • " + constraint.getHumanReadableCondition());
                    }
                }

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

    private Set<SootMethod> findCallersUsingCallGraph(SootMethod targetMethod, int maxCallers) {
        System.out.println("\n          === LIMITED CALLER DISCOVERY for " + targetMethod.getName() + " ===");
        System.out.println("             Max callers to find: " + maxCallers);

        Set<SootMethod> callGraphCallers = new HashSet<>();
        Set<SootMethod> allocationGraphCallers = new HashSet<>();

        // Method 1: Use call graph edges (with limit)
        CallGraph callGraph = graphAnalyzer.getCallGraph();
        if (callGraph != null) {
            System.out.println("             Scanning CallGraph for callers...");
            Iterator<Edge> incomingEdges = callGraph.edgesInto(targetMethod);
            int callGraphCount = 0;

            while (incomingEdges.hasNext() && callGraphCount < maxCallers) {
                Edge edge = incomingEdges.next();
                SootMethod caller = edge.src();
                if (caller != null) {
                    callGraphCallers.add(caller);
                    callGraphCount++;
                    System.out.println("               CallGraph found: " + caller.getName());
                }
            }
            System.out.println("             CallGraph found: " + callGraphCallers.size() + " callers (limit: "
                    + maxCallers + ")");
        } else {
            System.out.println("             ERROR: CallGraph is null!");
        }

        // Method 2: Scan allocation graphs for METHOD_CALL nodes (with limit)
        System.out.println("             Scanning AllocationGraphs for callers...");
        Map<SootMethod, AllocationGraph> methodGraphs = graphAnalyzer.getMethodGraphs();
        int scannedGraphs = 0;
        int allocationGraphCount = 0;
        int remainingSlots = maxCallers - callGraphCallers.size();

        if (remainingSlots > 0) {
            for (Map.Entry<SootMethod, AllocationGraph> entry : methodGraphs.entrySet()) {
                if (allocationGraphCount >= remainingSlots) {
                    break; // Stop scanning once we hit the limit
                }

                SootMethod method = entry.getKey();
                AllocationGraph graph = entry.getValue();
                scannedGraphs++;

                // Skip if already found in call graph
                if (callGraphCallers.contains(method)) {
                    continue;
                }

                // Check if this method calls our target
                if (methodCallsTarget(graph, targetMethod)) {
                    allocationGraphCallers.add(method);
                    allocationGraphCount++;
                    System.out.println("               AllocationGraph found: " + method.getName());
                }
            }
        }

        System.out.println("             AllocationGraph scanned " + scannedGraphs + " graphs, found: "
                + allocationGraphCallers.size() + " callers");

        // Combine results (respecting total limit)
        Set<SootMethod> allCallers = new HashSet<>();
        allCallers.addAll(callGraphCallers);
        allCallers.addAll(allocationGraphCallers);

        // Ensure we don't exceed the maximum
        if (allCallers.size() > maxCallers) {
            Set<SootMethod> limitedCallers = new HashSet<>();
            int count = 0;
            for (SootMethod caller : allCallers) {
                if (count >= maxCallers)
                    break;
                limitedCallers.add(caller);
                count++;
            }
            allCallers = limitedCallers;
        }

        // Print analysis
        Set<SootMethod> onlyInCallGraph = new HashSet<>(callGraphCallers);
        onlyInCallGraph.removeAll(allocationGraphCallers);

        Set<SootMethod> onlyInAllocationGraph = new HashSet<>(allocationGraphCallers);
        onlyInAllocationGraph.removeAll(callGraphCallers);

        Set<SootMethod> inBoth = new HashSet<>(callGraphCallers);
        inBoth.retainAll(allocationGraphCallers);

        System.out.println("             --- Limited Caller Discovery Summary ---");
        System.out
                .println("               Total unique callers: " + allCallers.size() + " (limit: " + maxCallers + ")");
        System.out.println("               Only in CallGraph: " + onlyInCallGraph.size());
        System.out.println("               Only in AllocationGraph: " + onlyInAllocationGraph.size());
        System.out.println("               In both sources: " + inBoth.size());

        return allCallers;
    }

    /**
     * Extract constraints from caller method using step-by-step targeting approach
     */
    private List<Constraint> extractConstraintsForCaller(SootMethod callerMethod, SootMethod targetMethod) {
        AllocationGraph graph = graphAnalyzer.getMethodGraphs().get(callerMethod);
        if (graph == null) {
            return new ArrayList<>();
        }

        // Find METHOD_CALL nodes that call the target method
        List<AllocationNode> methodCallNodes = findMethodCallNodes(graph, targetMethod);
        if (methodCallNodes.isEmpty()) {
            return new ArrayList<>();
        }

        List<Constraint> allConstraints = new ArrayList<>();

        // For each method call node, build constraints using step-by-step targeting
        for (AllocationNode methodCallNode : methodCallNodes) {
            System.out.println("        Analyzing call node: " + methodCallNode.getId());
            List<Constraint> constraints = buildStepByStepConstraints(graph, methodCallNode, callerMethod);
            allConstraints.addAll(constraints);
            System.out.println("           Generated " + constraints.size() + " constraints");
        }

        return allConstraints;
    }

    /**
     * Find METHOD_CALL nodes in the graph that call the target method
     */
    private List<AllocationNode> findMethodCallNodes(AllocationGraph graph, SootMethod targetMethod) {
        List<AllocationNode> methodCallNodes = new ArrayList<>();

        for (AllocationNode node : graph.getNodes()) {
            if (node.getType() == NodeType.METHOD_CALL) {
                InvokeExpr invoke = node.getMethodCall();
                if (invoke != null && invoke.getMethod().equals(targetMethod)) {
                    methodCallNodes.add(node);
                }
            }
        }

        return methodCallNodes;
    }

    /**
     * Build constraints using step-by-step targeting approach
     * Start from method call and move backward through conditions
     */
    private List<Constraint> buildStepByStepConstraints(AllocationGraph graph, AllocationNode startNode,
            SootMethod method) {

        System.out.println("          Building step-by-step constraints from: " + startNode.getId());

        List<Constraint> constraints = new ArrayList<>();
        AllocationNode currentTarget = startNode;
        Set<AllocationNode> visited = new HashSet<>();
        int stepCount = 0;

        // Move backward through graph, processing each condition with its immediate
        // target
        while (currentTarget != null && !visited.contains(currentTarget)) {
            stepCount++;
            visited.add(currentTarget);

            System.out.println("             Step " + stepCount + ": Analyzing target node " + currentTarget.getId());

            // Find predecessor condition nodes (IF_CONDITION or SWITCH)
            List<AllocationNode> predecessorConditions = findPredecessorConditions(graph, currentTarget);

            if (predecessorConditions.isEmpty()) {
                System.out.println("               No more predecessor conditions found");
                break;
            }

            System.out.println("               Found " + predecessorConditions.size() + " predecessor conditions");

            // Process each predecessor condition
            for (AllocationNode conditionNode : predecessorConditions) {
                System.out.println("                 Processing condition: " + conditionNode.getId() +
                        " (type: " + conditionNode.getType() + ")");

                if (conditionNode.getType() == NodeType.IF_CONDITION) {
                    Constraint constraint = extractConstraintForCondition(conditionNode, currentTarget, method);
                    if (constraint != null) {
                        constraints.add(0, constraint); // Add to beginning (building backward)
                        System.out.println("                   Generated constraint: " +
                                constraint.getHumanReadableCondition());

                        // DEBUG: Stage 6 - Path Assembly (for each constraint added)
                        if (interactionLogger != null && interactionLogger.isEnabled()) {
                            interactionLogger.logPathAssembly(
                                    "temp_path_" + System.nanoTime(), // Temporary path ID
                                    constraints.size(),
                                    true, // Assume valid for now
                                    null);
                        }
                    } else {
                        System.out.println("                   Failed to generate constraint");
                    }

                    // Move to this condition as the new target for next iteration
                    currentTarget = conditionNode;

                } else if (conditionNode.getType() == NodeType.SWITCH) {
                    // Handle switch nodes similarly
                    Constraint constraint = extractSwitchConstraint(conditionNode, currentTarget, method);
                    if (constraint != null) {
                        constraints.add(0, constraint);
                        System.out.println("                   Generated switch constraint: " +
                                constraint.getHumanReadableCondition());

                        // DEBUG: Stage 6 - Path Assembly
                        if (interactionLogger != null && interactionLogger.isEnabled()) {
                            interactionLogger.logPathAssembly(
                                    "temp_path_" + System.nanoTime(),
                                    constraints.size(),
                                    true,
                                    null);
                        }
                    }

                    currentTarget = conditionNode;
                }
            }
        }

        System.out.println("          Step-by-step analysis complete:");
        System.out.println("             - Total steps: " + stepCount);
        System.out.println("             - Generated constraints: " + constraints.size());

        return constraints;
    }

    /**
     * Find predecessor nodes that are IF_CONDITION or SWITCH
     */
    private List<AllocationNode> findPredecessorConditions(AllocationGraph graph, AllocationNode targetNode) {
        List<AllocationNode> conditionPredecessors = new ArrayList<>();

        // Get all predecessors of the target node
        Set<AllocationNode> predecessors = graph.getPredecessors(targetNode);

        for (AllocationNode pred : predecessors) {
            if (pred.getType() == NodeType.IF_CONDITION || pred.getType() == NodeType.SWITCH) {
                conditionPredecessors.add(pred);
            } else {
                // If predecessor is not a condition, recursively check its predecessors
                conditionPredecessors.addAll(findPredecessorConditions(graph, pred));
            }
        }

        return conditionPredecessors;
    }

    /**
     * Extract constraint for a single IF condition with immediate target
     */
    private Constraint extractConstraintForCondition(AllocationNode conditionNode, AllocationNode targetNode,
            SootMethod method) {
        if (conditionNode.getType() != NodeType.IF_CONDITION) {
            return null;
        }

        Unit ifUnit = conditionNode.getUnit();
        if (!(ifUnit instanceof IfStmt)) {
            return null;
        }

        // Use ConstraintExtractor with step-by-step targeting approach
        return constraintExtractor.extractSingleConditionConstraint(conditionNode, targetNode, method);
    }

    /**
     * Extract constraint for a SWITCH node
     */
    private Constraint extractSwitchConstraint(AllocationNode switchNode, AllocationNode targetNode,
            SootMethod method) {
        if (switchNode.getType() != NodeType.SWITCH) {
            return null;
        }

        // For now, return a basic switch constraint
        // TODO: Implement proper switch constraint extraction with LLM
        Unit switchUnit = switchNode.getUnit();
        String constraintId = generateConstraintId(method, switchUnit, "switch");

        return new SwitchConstraint(
                constraintId, method, switchUnit, "switch_condition",
                "switch_var", "case_value", false);
    }

    /**
     * Find all methods that call the target method using hybrid approach
     */
    private Set<SootMethod> findAllCallers(SootMethod targetMethod) {
        System.out.println("\n          === CALLER DISCOVERY for " + targetMethod.getName() + " ===");

        Set<SootMethod> callGraphCallers = new HashSet<>();
        Set<SootMethod> allocationGraphCallers = new HashSet<>();

        // Method 1: Use call graph edges
        CallGraph callGraph = graphAnalyzer.getCallGraph();
        if (callGraph != null) {
            System.out.println("             Scanning CallGraph for callers...");
            Iterator<Edge> incomingEdges = callGraph.edgesInto(targetMethod);
            while (incomingEdges.hasNext()) {
                Edge edge = incomingEdges.next();
                SootMethod caller = edge.src();
                if (caller != null) {
                    callGraphCallers.add(caller);
                    System.out.println("               CallGraph found: " + caller.getName());
                }
            }
            System.out.println("             CallGraph total: " + callGraphCallers.size() + " callers");
        } else {
            System.out.println("             ERROR: CallGraph is null!");
        }

        // Method 2: Scan allocation graphs for METHOD_CALL nodes
        System.out.println("             Scanning AllocationGraphs for callers...");
        Map<SootMethod, AllocationGraph> methodGraphs = graphAnalyzer.getMethodGraphs();
        int scannedGraphs = 0;
        for (Map.Entry<SootMethod, AllocationGraph> entry : methodGraphs.entrySet()) {
            SootMethod method = entry.getKey();
            AllocationGraph graph = entry.getValue();
            scannedGraphs++;

            // Check if this method calls our target
            if (methodCallsTarget(graph, targetMethod)) {
                allocationGraphCallers.add(method);
                System.out.println("               AllocationGraph found: " + method.getName());
            }
        }
        System.out.println("             AllocationGraph scanned " + scannedGraphs + " graphs, found: "
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

        System.out.println("             --- Caller Discovery Summary ---");
        System.out.println("               Total unique callers: " + allCallers.size());
        System.out.println("               Only in CallGraph: " + onlyInCallGraph.size());
        System.out.println("               Only in AllocationGraph: " + onlyInAllocationGraph.size());
        System.out.println("               In both sources: " + inBoth.size());

        return allCallers;
    }

    /**
     * Check if an allocation graph contains calls to target method
     */
    private boolean methodCallsTarget(AllocationGraph graph, SootMethod targetMethod) {
        Set<AllocationNode> allNodes = graph.getNodes();

        for (AllocationNode node : allNodes) {
            if (node.getType() == NodeType.METHOD_CALL) {
                InvokeExpr invoke = node.getMethodCall();
                if (invoke != null && invoke.getMethod().equals(targetMethod)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Create a complete constraint path from method sequence and constraints
     */
    private void createCompletePath(List<SootMethod> methodSequence, List<Constraint> constraints,
            List<ConstraintPath> allPaths) {

        System.out.println("\n        ====================================================");
        System.out.println("                   CREATING COMPLETE PATH");
        System.out.println("        ====================================================");

        // DEBUG: Print complete method sequence
        System.out.println("        Complete method sequence (" + methodSequence.size() + " methods):");
        for (int i = 0; i < methodSequence.size(); i++) {
            System.out.println("          " + String.format("%2d", i + 1) + ". " + methodSequence.get(i).getName());
        }

        System.out.println("        Final constraints (" + constraints.size() + "):");
        for (int i = 0; i < constraints.size(); i++) {
            Constraint c = constraints.get(i);
            System.out.println("          " + String.format("%2d", i + 1) + ". " + c.getHumanReadableCondition());
            if (c instanceof EnhancedConditionalConstraint) {
                EnhancedConditionalConstraint enhanced = (EnhancedConditionalConstraint) c;
                System.out.println("             Format1: " + enhanced.getFormat1());
                System.out.println("             Format2: " + enhanced.getFormat2());
                System.out.println("             Format3: " + enhanced.getFormat3());
            }
        }

        if (methodSequence.isEmpty()) {
            System.out.println("        ERROR: Cannot create path - empty method sequence");
            return;
        }

        SootMethod targetMethod = methodSequence.get(methodSequence.size() - 1);
        String pathId = generatePathId(methodSequence, constraints);

        // Validate path
        boolean isValid = validatePath(methodSequence, constraints);
        String invalidReason = null;
        if (!isValid) {
            invalidReason = "Path validation failed: " + getValidationFailureReason(methodSequence, constraints);
        }

        System.out.println("        Path validation: " + (isValid ? "VALID" : "INVALID"));
        if (!isValid) {
            System.out.println("           Reason: " + invalidReason);
        }

        ConstraintPath path = new ConstraintPath(pathId, targetMethod, methodSequence, constraints, isValid);
        if (!isValid) {
            path.invalidatePath(invalidReason);
        }

        allPaths.add(path);

        // COMPREHENSIVE DEBUG: Stage 6 - Path Assembly (Complete path creation)
        System.out.println("\n        >>> DEBUG: Stage 6 - Path Assembly (Complete) <<<");
        System.out.println("        DEBUG: Created constraint path: " + pathId);
        System.out.println("        DEBUG: Target method: " + targetMethod.getName());
        System.out.println("        DEBUG: Total methods in path: " + methodSequence.size());
        System.out.println("        DEBUG: Total constraints in path: " + constraints.size());
        System.out.println("        DEBUG: Path validation: " + (isValid ? "VALID" : "INVALID"));
        if (!isValid) {
            System.out.println("        DEBUG: Invalid reason: " + invalidReason);
        }
        System.out.println("        DEBUG: Path added to collection, total paths: " + allPaths.size());

        // Log to LLM interaction logger
        if (interactionLogger != null && interactionLogger.isEnabled()) {
            interactionLogger.logPathAssembly(pathId, constraints.size(), isValid, invalidReason);
        }

        System.out.println("        ====================================================");
        System.out.println("        Path creation complete: " + pathId);
        System.out.println("        ====================================================\n");
    }

    /**
     * Generate unique path ID
     */
    private String generatePathId(List<SootMethod> methodSequence, List<Constraint> constraints) {
        return "path_" + System.nanoTime() + "_" + methodSequence.size() + "m_" + constraints.size() + "c";
    }

    /**
     * Validate that the path and constraints are consistent
     */
    private boolean validatePath(List<SootMethod> methodSequence, List<Constraint> constraints) {
        // Basic validation - path should have at least one method
        if (methodSequence.isEmpty()) {
            return false;
        }

        // All constraints should be satisfiable (basic check)
        for (Constraint constraint : constraints) {
            if (constraint.getHumanReadableCondition() == null ||
                    constraint.getHumanReadableCondition().trim().isEmpty()) {
                return false;
            }
        }

        // Check for contradictory constraints
        for (int i = 0; i < constraints.size(); i++) {
            for (int j = i + 1; j < constraints.size(); j++) {
                if (!constraints.get(i).isCompatibleWith(constraints.get(j))) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Get detailed reason for validation failure
     */
    private String getValidationFailureReason(List<SootMethod> methodSequence, List<Constraint> constraints) {
        if (methodSequence.isEmpty()) {
            return "Empty method sequence";
        }

        for (Constraint constraint : constraints) {
            if (constraint.getHumanReadableCondition() == null ||
                    constraint.getHumanReadableCondition().trim().isEmpty()) {
                return "Empty constraint found: " + constraint.getId();
            }
        }

        // Check for contradictory constraints
        for (int i = 0; i < constraints.size(); i++) {
            for (int j = i + 1; j < constraints.size(); j++) {
                if (!constraints.get(i).isCompatibleWith(constraints.get(j))) {
                    return "Incompatible constraints: " + constraints.get(i).getId() +
                            " vs " + constraints.get(j).getId();
                }
            }
        }

        return "Unknown validation failure";
    }

    /**
     * Generate unique constraint ID
     */
    private String generateConstraintId(SootMethod method, Unit unit, String type) {
        return method.getSignature().hashCode() + "_" + unit.hashCode() + "_" + type;
    }

    /**
     * Cleanup resources
     */
    public void cleanup() {
        methodToCallers.clear();
        System.out.println("ConstraintPathBuilder cleanup complete");
    }
}