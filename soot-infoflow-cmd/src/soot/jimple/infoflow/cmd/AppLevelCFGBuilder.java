package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * Builds app-level CFG by connecting method-level CFGs through call sites
 */
public class AppLevelCFGBuilder {

    private final String appPackageName;
    private final AppMethodDiscovery methodDiscovery;
    private final BlockCFGExtractor cfgExtractor;

    // Method CFGs
    private Map<SootMethod, BlockCFGExtractor.MethodCFG> methodCFGs;
    private Set<SootMethod> appMethods;

    // App-level CFG nodes
    private Map<String, AppCFGNode> appCFGNodes;
    private Set<String> processedNodes;

    public AppLevelCFGBuilder(String appPackageName) {
        this.appPackageName = appPackageName;
        this.methodDiscovery = new AppMethodDiscovery(appPackageName);
        this.cfgExtractor = new BlockCFGExtractor();
        this.methodCFGs = new HashMap<>();
        this.appCFGNodes = new HashMap<>();
        this.processedNodes = new HashSet<>();
    }

    /**
     * Build complete app-level CFG starting from entry points
     */
    public void buildAppCFG(Set<SootMethod> entryPoints) {
        System.out.println("=== Building App-Level CFG ===");

        // Phase 1: Create method-level CFGs for all app methods
        System.out.println("Phase 1: Creating method-level CFGs...");
        createAllMethodCFGs();

        // Phase 2: Build app-level CFG from entry points (keep for graph structure)
        System.out.println("Phase 2: Connecting inter-procedural edges...");
        for (SootMethod entryPoint : entryPoints) {
            if (isAppMethod(entryPoint)) {
                processEntryPoint(entryPoint);
            }
        }

        System.out.println("App-level CFG completed:");
        System.out.println("  Total app CFG nodes: " + appCFGNodes.size());
        System.out.println("  Processed nodes: " + processedNodes.size());
    }

    /**
     * Build composite paths using new composite path approach
     */
    public List<CompositePathBuilder.CompositePath> buildCompositePaths(Set<SootMethod> entryPoints) {
        System.out.println("\n=== Building Composite Paths (New Approach) ===");

        // Ensure CFG is built first
        if (methodCFGs.isEmpty()) {
            buildAppCFG(entryPoints);
        }

        // Initialize components for composite path building
        MethodPathEnumerator pathEnumerator = new MethodPathEnumerator();
        CallSiteAnalyzer callSiteAnalyzer = new CallSiteAnalyzer(appPackageName);

        // Analyze call sites in the app CFG
        callSiteAnalyzer.analyzeCallSites(appCFGNodes);
        callSiteAnalyzer.printCallSiteSummary();

        // Build composite paths
        CompositePathBuilder pathBuilder = new CompositePathBuilder(
                appPackageName, pathEnumerator, callSiteAnalyzer, methodCFGs);

        List<CompositePathBuilder.CompositePath> compositePaths = pathBuilder.buildCompositePaths(entryPoints);

        // Assign path IDs
        for (int i = 0; i < compositePaths.size(); i++) {
            compositePaths.get(i).setPathId(i + 1);
        }

        return compositePaths;
    }

    /**
     * Phase 1: Create method-level CFGs for all app methods
     */
    private void createAllMethodCFGs() {
        appMethods = methodDiscovery.getAppMethods();

        for (SootMethod method : appMethods) {
            BlockCFGExtractor.MethodCFG cfg = cfgExtractor.extractCFG(method);
            if (cfg != null) {
                methodCFGs.put(method, cfg);

                // Create app CFG nodes for each block
                for (BlockCFGExtractor.CFGBlock block : cfg.blocks) {
                    String nodeId = getNodeId(method, block);
                    AppCFGNode appNode = new AppCFGNode(nodeId, method, block);
                    appCFGNodes.put(nodeId, appNode);
                }
            }
        }

        System.out.println("Created CFGs for " + methodCFGs.size() + " methods");
        System.out.println("Created " + appCFGNodes.size() + " app CFG nodes");
    }

    /**
     * Phase 2: Process entry point and build inter-procedural connections
     */
    private void processEntryPoint(SootMethod entryPoint) {
        BlockCFGExtractor.MethodCFG entryCFG = methodCFGs.get(entryPoint);
        if (entryCFG == null || entryCFG.getEntryBlocks().isEmpty()) {
            return;
        }

        // Start from first block of entry method
        BlockCFGExtractor.CFGBlock firstBlock = entryCFG.getEntryBlocks().get(0);
        String firstNodeId = getNodeId(entryPoint, firstBlock);

        processBlock(firstNodeId);
    }

    /**
     * Recursively process a block and its successors
     */
    private void processBlock(String nodeId) {
        if (processedNodes.contains(nodeId)) {
            return; // Already processed
        }

        processedNodes.add(nodeId);
        AppCFGNode currentNode = appCFGNodes.get(nodeId);
        if (currentNode == null) {
            return;
        }

        // Process statements in this block
        processStatementsInBlock(currentNode);

        // Process successor blocks within same method
        for (Integer successorId : currentNode.block.successors) {
            String successorNodeId = getNodeId(currentNode.method, successorId);
            AppCFGNode successorNode = appCFGNodes.get(successorNodeId);
            if (successorNode != null) {
                currentNode.addSuccessor(successorNodeId);
                processBlock(successorNodeId);
            }
        }
    }

    /**
     * Process units in a block to find method calls
     */
    private void processStatementsInBlock(AppCFGNode currentNode) {
        List<Unit> units = currentNode.block.units;

        for (int i = 0; i < units.size(); i++) {
            Unit unit = units.get(i);

            if (isInvokeUnit(unit)) {
                InvokeExpr invokeExpr = getInvokeExpr(unit);
                if (invokeExpr != null) {
                    SootMethod targetMethod = invokeExpr.getMethod();

                    if (isAppMethod(targetMethod)) {
                        System.out.println("Found app method call: " + targetMethod.getName() +
                                " in " + currentNode.method.getName());
                        createInterProceduralEdges(currentNode, targetMethod, i);
                    }
                }
            }
        }
    }

    /**
     * Check if unit is a method invocation using instanceof
     */
    private boolean isInvokeUnit(Unit unit) {
        if (unit instanceof InvokeStmt) {
            return true;
        }
        if (unit instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) unit;
            return assign.getRightOp() instanceof InvokeExpr;
        }
        return false;
    }

    /**
     * Extract InvokeExpr from unit
     */
    private InvokeExpr getInvokeExpr(Unit unit) {
        if (unit instanceof InvokeStmt) {
            return ((InvokeStmt) unit).getInvokeExpr();
        }
        if (unit instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) unit;
            if (assign.getRightOp() instanceof InvokeExpr) {
                return (InvokeExpr) assign.getRightOp();
            }
        }
        return null;
    }

    /**
     * Create call and return edges for method invocation
     */
    private void createInterProceduralEdges(AppCFGNode callerNode, SootMethod targetMethod, int callUnitIndex) {
        BlockCFGExtractor.MethodCFG targetCFG = methodCFGs.get(targetMethod);
        if (targetCFG == null || targetCFG.getEntryBlocks().isEmpty()) {
            return;
        }

        // Create call edge: caller -> target entry
        BlockCFGExtractor.CFGBlock targetEntryBlock = targetCFG.getEntryBlocks().get(0);
        String targetEntryNodeId = getNodeId(targetMethod, targetEntryBlock);
        callerNode.addCallEdge(targetEntryNodeId);

        System.out.println("Created call edge: " + callerNode.nodeId + " -> " + targetEntryNodeId);

        // Create return edges: target exits -> caller continuation
        String continuationNodeId = findContinuationNode(callerNode, callUnitIndex);
        if (continuationNodeId != null) {
            for (BlockCFGExtractor.CFGBlock exitBlock : targetCFG.getExitBlocks()) {
                String exitNodeId = getNodeId(targetMethod, exitBlock);
                AppCFGNode exitNode = appCFGNodes.get(exitNodeId);
                if (exitNode != null) {
                    exitNode.addReturnEdge(continuationNodeId);
                    System.out.println("Created return edge: " + exitNodeId + " -> " + continuationNodeId);
                }
            }
        }

        // Recursively process target method
        processBlock(targetEntryNodeId);
    }

    /**
     * Find continuation point after method call
     */
    private String findContinuationNode(AppCFGNode callerNode, int callUnitIndex) {
        // If call is not the last unit in block, continuation is in same block
        if (callUnitIndex < callerNode.block.units.size() - 1) {
            return callerNode.nodeId; // Same block continues
        }

        // If call is last unit, continuation is successor blocks
        if (!callerNode.block.successors.isEmpty()) {
            Integer firstSuccessor = callerNode.block.successors.iterator().next();
            return getNodeId(callerNode.method, firstSuccessor);
        }

        return null; // No continuation (method ends)
    }

    /**
     * Check if method belongs to app package
     */
    private boolean isAppMethod(SootMethod method) {
        return method.getDeclaringClass().getPackageName().startsWith(appPackageName);
    }

    /**
     * Generate unique node ID
     */
    private String getNodeId(SootMethod method, BlockCFGExtractor.CFGBlock block) {
        return method.getSignature() + "_block_" + block.sootIndex;
    }

    /**
     * Generate node ID from method and block index
     */
    private String getNodeId(SootMethod method, int blockIndex) {
        return method.getSignature() + "_block_" + blockIndex;
    }

    /**
     * Print app-level CFG
     */
    public void printAppCFG() {
        System.out.println("\n=== App-Level CFG ===");

        for (AppCFGNode node : appCFGNodes.values()) {
            if (processedNodes.contains(node.nodeId)) {
                System.out.println("\nNode: " + node.nodeId);
                System.out.println("Method: " + node.method.getName());
                System.out.println("Block: " + node.block.sootIndex);

                if (!node.successors.isEmpty()) {
                    System.out.println("Successors: " + node.successors);
                }
                if (!node.callEdges.isEmpty()) {
                    System.out.println("Call edges: " + node.callEdges);
                }
                if (!node.returnEdges.isEmpty()) {
                    System.out.println("Return edges: " + node.returnEdges);
                }
            }
        }
    }

    /**
     * Print simple text-based graph visualization
     */
    public void printGraphVisualization() {
        System.out.println("\n=== Graph Visualization (Adjacency List) ===");

        // Group nodes by method for better readability
        Map<String, List<AppCFGNode>> nodesByMethod = new HashMap<>();

        for (AppCFGNode node : appCFGNodes.values()) {
            if (processedNodes.contains(node.nodeId)) {
                String methodName = node.method.getName();
                nodesByMethod.computeIfAbsent(methodName, k -> new ArrayList<>()).add(node);
            }
        }

        // Sort methods alphabetically
        List<String> sortedMethods = new ArrayList<>(nodesByMethod.keySet());
        Collections.sort(sortedMethods);

        for (String methodName : sortedMethods) {
            System.out.println("\n--- Method: " + methodName + " ---");

            List<AppCFGNode> methodNodes = nodesByMethod.get(methodName);
            methodNodes.sort(Comparator.comparingInt(n -> n.block.sootIndex));

            for (AppCFGNode node : methodNodes) {
                String blockName = methodName + "_block_" + node.block.sootIndex;
                System.out.print(blockName + " -> ");

                List<String> allEdges = new ArrayList<>();

                // Add successor edges
                for (String successor : node.successors) {
                    String succName = extractNodeName(successor);
                    allEdges.add(succName + " (successor)");
                }

                // Add call edges
                for (String callTarget : node.callEdges) {
                    String callName = extractNodeName(callTarget);
                    allEdges.add(callName + " (CALL)");
                }

                // Add return edges
                for (String returnTarget : node.returnEdges) {
                    String returnName = extractNodeName(returnTarget);
                    allEdges.add(returnName + " (RETURN)");
                }

                if (allEdges.isEmpty()) {
                    System.out.println("[ TERMINAL ]");
                } else {
                    System.out.println("[ " + String.join(", ", allEdges) + " ]");
                }
            }
        }

        System.out.println("\n=== Edge Legend ===");
        System.out.println("(successor) = Normal control flow within method");
        System.out.println("(CALL)      = Method call to another method");
        System.out.println("(RETURN)    = Return from method call");
        System.out.println("[ TERMINAL ] = No outgoing edges");
    }

    /**
     * Extract readable node name from full node ID
     */
    private String extractNodeName(String nodeId) {
        // Convert full signature to simple method_block format
        if (nodeId.contains("_block_")) {
            String[] parts = nodeId.split("_block_");
            if (parts.length == 2) {
                String signature = parts[0];
                String blockId = parts[1];

                // Extract method name from signature
                String methodName = extractMethodNameFromSignature(signature);
                return methodName + "_block_" + blockId;
            }
        }
        return nodeId;
    }

    /**
     * Extract method name from full signature
     */
    private String extractMethodNameFromSignature(String signature) {
        // Extract from format: "<class: returnType methodName(params)>"
        if (signature.contains(": ") && signature.contains(" ")) {
            String[] parts = signature.split(": ");
            if (parts.length >= 2) {
                String methodPart = parts[1];
                String[] methodParts = methodPart.split(" ");
                if (methodParts.length >= 2) {
                    String methodWithParams = methodParts[1];
                    if (methodWithParams.contains("(")) {
                        return methodWithParams.substring(0, methodWithParams.indexOf("("));
                    }
                    return methodWithParams;
                }
            }
        }
        return signature;
    }

    /**
     * Print composite paths in detailed format
     */
    public void printCompositePaths(List<CompositePathBuilder.CompositePath> compositePaths) {
        System.out.println("\n=== Composite Paths ===");
        System.out.println("Total composite paths: " + compositePaths.size());

        for (CompositePathBuilder.CompositePath path : compositePaths) {
            printDetailedCompositePath(path);
        }

        printCompositePathStatistics(compositePaths);
    }

    /**
     * Print detailed information about a single composite path
     */
    private void printDetailedCompositePath(CompositePathBuilder.CompositePath compositePath) {
        System.out.println("\n=== Composite Path " + compositePath.getPathId() + " ===");
        System.out.println("Entry Point: " + compositePath.getEntryPoint().getName());
        System.out.println("Total Blocks: " + compositePath.getTotalBlocks());
        System.out.println("Method Executions: " + compositePath.getMethodExecutions().size());

        System.out.println("Execution Flow:");
        int execNumber = 1;
        for (CompositePathBuilder.CompositePath.MethodExecution execution : compositePath.getMethodExecutions()) {
            String indent = execution.callerExecution != null ? "  " : "";
            String callInfo = execution.callSite != null
                    ? " (called from " + execution.callerExecution.methodPath.method.getName() + ")"
                    : "";

            System.out.println(indent + execNumber + ". " + execution.methodPath.method.getName() +
                    " - " + execution.methodPath.getPathSummary() + callInfo);
            execNumber++;
        }
    }

    /**
     * Print statistics about composite paths
     */
    private void printCompositePathStatistics(List<CompositePathBuilder.CompositePath> compositePaths) {
        System.out.println("\n=== Composite Path Statistics ===");

        // Group by entry point
        Map<String, Integer> pathsByEntry = new HashMap<>();
        Map<String, Integer> lengthDistribution = new HashMap<>();

        for (CompositePathBuilder.CompositePath path : compositePaths) {
            String entryName = path.getEntryPoint().getName();
            pathsByEntry.put(entryName, pathsByEntry.getOrDefault(entryName, 0) + 1);

            String lengthRange = getPathLengthRange(path.getTotalBlocks());
            lengthDistribution.put(lengthRange, lengthDistribution.getOrDefault(lengthRange, 0) + 1);
        }

        System.out.println("Paths by entry point:");
        for (Map.Entry<String, Integer> entry : pathsByEntry.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue() + " paths");
        }

        System.out.println("\nPath length distribution:");
        for (Map.Entry<String, Integer> entry : lengthDistribution.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue() + " paths");
        }

        if (!compositePaths.isEmpty()) {
            int minBlocks = compositePaths.stream().mapToInt(CompositePathBuilder.CompositePath::getTotalBlocks).min()
                    .orElse(0);
            int maxBlocks = compositePaths.stream().mapToInt(CompositePathBuilder.CompositePath::getTotalBlocks).max()
                    .orElse(0);
            double avgBlocks = compositePaths.stream().mapToInt(CompositePathBuilder.CompositePath::getTotalBlocks)
                    .average().orElse(0);

            System.out.println("\nPath complexity:");
            System.out.println("  Shortest path: " + minBlocks + " blocks");
            System.out.println("  Longest path: " + maxBlocks + " blocks");
            System.out.println("  Average length: " + String.format("%.1f", avgBlocks) + " blocks");
        }
    }

    /**
     * Get path length range for statistics
     */
    private String getPathLengthRange(int length) {
        if (length <= 5)
            return "1-5 blocks";
        if (length <= 10)
            return "6-10 blocks";
        if (length <= 20)
            return "11-20 blocks";
        return "20+ blocks";
    }

    /**
     * Generate Angr guidance format for composite paths
     */
    public void generateAngrGuidance(List<CompositePathBuilder.CompositePath> compositePaths, String outputFile) {
        System.out.println("\n=== Generating Angr Guidance ===");

        try (java.io.FileWriter writer = new java.io.FileWriter(outputFile)) {
            writer.write("# Angr Symbolic Execution Guidance\n");
            writer.write("# Generated from App-Level CFG Analysis\n\n");

            for (CompositePathBuilder.CompositePath path : compositePaths) {
                writer.write("## Composite Path " + path.getPathId() + "\n");
                writer.write("# Entry: " + path.getEntryPoint().getName() + "\n");
                writer.write("# Summary: " + path.getPathSummary() + "\n");

                writer.write("path_" + path.getPathId() + " = {\n");
                writer.write("    'entry_point': '" + path.getEntryPoint().getName() + "',\n");
                writer.write("    'method_executions': [\n");

                for (CompositePathBuilder.CompositePath.MethodExecution execution : path.getMethodExecutions()) {
                    writer.write("        {\n");
                    writer.write("            'method': '" + execution.methodPath.method.getName() + "',\n");
                    writer.write("            'blocks': " + execution.methodPath.blockSequence.size() + ",\n");
                    writer.write("            'path_summary': '" + execution.methodPath.getPathSummary() + "'\n");
                    writer.write("        },\n");
                }

                writer.write("    ]\n");
                writer.write("}\n\n");
            }

            System.out.println("Angr guidance written to: " + outputFile);

        } catch (java.io.IOException e) {
            System.err.println("Error writing Angr guidance: " + e.getMessage());
        }
    }

    /**
     * App-level CFG node
     */
    public static class AppCFGNode {
        public final String nodeId;
        public final SootMethod method;
        public final BlockCFGExtractor.CFGBlock block;
        public final Set<String> successors;
        public final Set<String> callEdges;
        public final Set<String> returnEdges;

        public AppCFGNode(String nodeId, SootMethod method, BlockCFGExtractor.CFGBlock block) {
            this.nodeId = nodeId;
            this.method = method;
            this.block = block;
            this.successors = new HashSet<>();
            this.callEdges = new HashSet<>();
            this.returnEdges = new HashSet<>();
        }

        public void addSuccessor(String successorId) {
            successors.add(successorId);
        }

        public void addCallEdge(String targetId) {
            callEdges.add(targetId);
        }

        public void addReturnEdge(String continuationId) {
            returnEdges.add(continuationId);
        }
    }

    /**
     * Generate DOT visualization of the graph
     */
    public void generateDotVisualization(String filename) {
        DotGraphVisualizer visualizer = new DotGraphVisualizer(appCFGNodes, processedNodes);
        visualizer.generateDotFile(filename);
    }

    // Getters
    public Map<String, AppCFGNode> getAppCFGNodes() {
        return Collections.unmodifiableMap(appCFGNodes);
    }

    public Set<String> getProcessedNodes() {
        return Collections.unmodifiableSet(processedNodes);
    }

    public Map<SootMethod, BlockCFGExtractor.MethodCFG> getMethodCFGs() {
        return Collections.unmodifiableMap(methodCFGs);
    }
}