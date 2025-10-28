package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;

/**
 * Finds all possible execution paths through the app-level CFG using DFS
 */
public class AppLevelPathFinder {
    
    private final Map<String, AppLevelCFGBuilder.AppCFGNode> appCFGNodes;
    private List<ExecutionPath> allPaths;
    private int pathCounter;
    
    public AppLevelPathFinder(Map<String, AppLevelCFGBuilder.AppCFGNode> appCFGNodes) {
        this.appCFGNodes = appCFGNodes;
        this.allPaths = new ArrayList<>();
        this.pathCounter = 0;
    }
    
    /**
     * Find all execution paths starting from entry points
     */
    public void findAllPaths(Set<SootMethod> entryPoints) {
        System.out.println("\n=== Finding All Execution Paths ===");
        
        allPaths.clear();
        pathCounter = 0;
        
        for (SootMethod entryPoint : entryPoints) {
            findPathsFromEntryPoint(entryPoint);
        }
        
        System.out.println("\n=== Path Discovery Complete ===");
        System.out.println("Total paths found: " + allPaths.size());
    }
    
    /**
     * Find all paths starting from a specific entry point
     */
    private void findPathsFromEntryPoint(SootMethod entryPoint) {
        String entryNodeId = entryPoint.getSignature() + "_block_0";
        AppLevelCFGBuilder.AppCFGNode entryNode = appCFGNodes.get(entryNodeId);
        
        if (entryNode == null) {
            System.out.println("Entry node not found: " + entryNodeId);
            return;
        }
        
        System.out.println("\nStarting DFS from: " + entryPoint.getName());
        
        // Start DFS traversal
        List<String> currentPath = new ArrayList<>();
        Set<String> visitedInPath = new HashSet<>();
        
        dfsTraversal(entryNode, currentPath, visitedInPath, entryPoint);
    }
    
    /**
     * DFS traversal to find all paths
     */
    private void dfsTraversal(AppLevelCFGBuilder.AppCFGNode currentNode, 
                             List<String> currentPath, 
                             Set<String> visitedInPath,
                             SootMethod entryPoint) {
        
        // Add current node to path
        currentPath.add(currentNode.nodeId);
        visitedInPath.add(currentNode.nodeId);
        
        // Check if this is a terminal node (no outgoing edges)
        if (isTerminalNode(currentNode)) {
            // Found a complete path
            pathCounter++;
            ExecutionPath execPath = new ExecutionPath(pathCounter, new ArrayList<>(currentPath), entryPoint);
            allPaths.add(execPath);
            
            System.out.println("Path " + pathCounter + " found: " + execPath.getPathSummary());
        } else {
            // Continue DFS on all outgoing edges
            
            // Collect all possible next nodes
            Set<String> allNextNodes = new HashSet<>();
            allNextNodes.addAll(currentNode.successors);
            allNextNodes.addAll(currentNode.callEdges);
            allNextNodes.addAll(currentNode.returnEdges);
            
            // Visit each unvisited next node
            for (String nextNodeId : allNextNodes) {
                AppLevelCFGBuilder.AppCFGNode nextNode = appCFGNodes.get(nextNodeId);
                if (nextNode != null && !visitedInPath.contains(nextNodeId)) {
                    dfsTraversal(nextNode, currentPath, visitedInPath, entryPoint);
                }
            }
        }
        
        // Backtrack: remove current node from path and visited set
        currentPath.remove(currentPath.size() - 1);
        visitedInPath.remove(currentNode.nodeId);
    }
    
    /**
     * Check if node is terminal (no outgoing edges)
     */
    private boolean isTerminalNode(AppLevelCFGBuilder.AppCFGNode node) {
        return node.successors.isEmpty() && 
               node.callEdges.isEmpty() && 
               node.returnEdges.isEmpty();
    }
    
    /**
     * Print all discovered paths
     */
    public void printAllPaths() {
        System.out.println("\n=== All Execution Paths ===");
        
        for (ExecutionPath path : allPaths) {
            path.printDetailedPath();
            System.out.println();
        }
        
        printPathStatistics();
    }
    
    /**
     * Print path statistics
     */
    public void printPathStatistics() {
        System.out.println("\n=== Path Statistics ===");
        System.out.println("Total paths: " + allPaths.size());
        
        // Group by entry point
        Map<String, Integer> pathsByEntry = new HashMap<>();
        Map<String, Integer> pathLengths = new HashMap<>();
        
        for (ExecutionPath path : allPaths) {
            String entryName = path.entryPoint.getName();
            pathsByEntry.put(entryName, pathsByEntry.getOrDefault(entryName, 0) + 1);
            
            String lengthRange = getPathLengthRange(path.pathNodes.size());
            pathLengths.put(lengthRange, pathLengths.getOrDefault(lengthRange, 0) + 1);
        }
        
        System.out.println("\nPaths by entry point:");
        for (Map.Entry<String, Integer> entry : pathsByEntry.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue() + " paths");
        }
        
        System.out.println("\nPath length distribution:");
        for (Map.Entry<String, Integer> entry : pathLengths.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue() + " paths");
        }
        
        // Find longest and shortest paths
        if (!allPaths.isEmpty()) {
            ExecutionPath shortest = allPaths.stream()
                .min(Comparator.comparingInt(p -> p.pathNodes.size())).get();
            ExecutionPath longest = allPaths.stream()
                .max(Comparator.comparingInt(p -> p.pathNodes.size())).get();
            
            System.out.println("\nShortest path: " + shortest.pathNodes.size() + " nodes");
            System.out.println("Longest path: " + longest.pathNodes.size() + " nodes");
        }
    }
    
    /**
     * Get path length range for statistics
     */
    private String getPathLengthRange(int length) {
        if (length <= 5) return "1-5 nodes";
        if (length <= 10) return "6-10 nodes";
        if (length <= 20) return "11-20 nodes";
        return "20+ nodes";
    }
    
    /**
     * Print paths in a specific format
     */
    public void printPathSummaries() {
        System.out.println("\n=== Path Summaries ===");
        
        for (ExecutionPath path : allPaths) {
            System.out.println("Path " + path.pathId + ": " + path.getPathSummary());
        }
    }
    
    /**
     * Get methods involved in paths
     */
    public void printMethodCoverage() {
        Set<String> coveredMethods = new HashSet<>();
        
        for (ExecutionPath path : allPaths) {
            for (String nodeId : path.pathNodes) {
                AppLevelCFGBuilder.AppCFGNode node = appCFGNodes.get(nodeId);
                if (node != null) {
                    coveredMethods.add(node.method.getName());
                }
            }
        }
        
        System.out.println("\n=== Method Coverage ===");
        System.out.println("Methods reached by paths: " + coveredMethods.size());
        for (String methodName : coveredMethods) {
            System.out.println("  " + methodName);
        }
    }
    
    /**
     * Represents a single execution path
     */
    public static class ExecutionPath {
        public final int pathId;
        public final List<String> pathNodes;
        public final SootMethod entryPoint;
        
        public ExecutionPath(int pathId, List<String> pathNodes, SootMethod entryPoint) {
            this.pathId = pathId;
            this.pathNodes = pathNodes;
            this.entryPoint = entryPoint;
        }
        
        /**
         * Get a brief summary of the path
         */
        public String getPathSummary() {
            if (pathNodes.isEmpty()) {
                return "Empty path";
            }
            
            String start = extractMethodAndBlock(pathNodes.get(0));
            String end = extractMethodAndBlock(pathNodes.get(pathNodes.size() - 1));
            
            return start + " -> ... -> " + end + " (" + pathNodes.size() + " nodes)";
        }
        
        /**
         * Print detailed path information
         */
        public void printDetailedPath() {
            System.out.println("=== Path " + pathId + " ===");
            System.out.println("Entry Point: " + entryPoint.getName());
            System.out.println("Path Length: " + pathNodes.size() + " nodes");
            System.out.println("Path Flow:");
            
            for (int i = 0; i < pathNodes.size(); i++) {
                String nodeId = pathNodes.get(i);
                String methodBlock = extractMethodAndBlock(nodeId);
                System.out.println("  " + (i + 1) + ". " + methodBlock);
            }
        }
        
        /**
         * Extract method name and block from node ID
         */
        private String extractMethodAndBlock(String nodeId) {
            // Extract from format: "method_signature_block_X"
            if (nodeId.contains("_block_")) {
                String[] parts = nodeId.split("_block_");
                if (parts.length == 2) {
                    String signature = parts[0];
                    String blockId = parts[1];
                    
                    // Extract method name from signature
                    String methodName = extractMethodName(signature);
                    return methodName + "_block_" + blockId;
                }
            }
            return nodeId;
        }
        
        /**
         * Extract method name from full signature
         */
        private String extractMethodName(String signature) {
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
    }
    
    // Getters
    public List<ExecutionPath> getAllPaths() {
        return Collections.unmodifiableList(allPaths);
    }
    
    public int getPathCount() {
        return allPaths.size();
    }
}