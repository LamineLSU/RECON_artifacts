package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

/**
 * Performs backward reachability analysis from a sink method.
 * Finds all paths from methods with no callers (roots) to the sink.
 */
public class BackwardReachabilityAnalyzer {

    private CallGraph callGraph;
    private boolean verbose;

    public BackwardReachabilityAnalyzer(CallGraph callGraph) {
        this.callGraph = callGraph;
        this.verbose = false;
    }

    /**
     * Enable/disable verbose output
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * Find all paths from root methods to the sink using backward traversal.
     * 
     * Algorithm:
     * 1. Start with sink in worklist
     * 2. For each method in worklist:
     * - Find all its callers
     * - If no callers: path is complete (reached root)
     * - If has callers: add each caller to worklist with extended path
     * - If already visited in this path: cycle detected, mark and stop
     * 3. Build ReachabilityGraph with all found paths
     */
    public ReachabilityGraph findPathsToSink(SootMethod sink) {
        if (verbose) {
            System.out.println("=== Starting Backward Reachability Analysis ===");
            System.out.println("Sink: " + sink.getSignature());
        }

        // Initialize result graph
        ReachabilityGraph reachGraph = new ReachabilityGraph(sink);

        // Worklist for traversal
        Queue<WorklistItem> worklist = new LinkedList<>();

        // Track all visited methods globally (across all paths)
        Set<SootMethod> globalVisited = new HashSet<>();

        // Initialize: start with sink
        ExecutionPath initialPath = new ExecutionPath("path-0");
        initialPath.addMethod(sink);
        Set<SootMethod> initialVisited = new HashSet<>();
        initialVisited.add(sink);

        worklist.add(new WorklistItem(sink, initialPath, initialVisited));

        int pathCounter = 1;
        int processedCount = 0;

        while (!worklist.isEmpty()) {
            WorklistItem item = worklist.poll();
            SootMethod current = item.method;
            ExecutionPath currentPath = item.path;
            Set<SootMethod> visitedInPath = item.visitedInPath;

            processedCount++;

            if (verbose && processedCount % 100 == 0) {
                System.out.println("Processed " + processedCount + " items, worklist size: " + worklist.size());
            }

            // Add current method to reachability graph
            reachGraph.addReachableMethod(current);
            globalVisited.add(current);

            // Find all callers of current method
            Iterator<Edge> edgesInto = callGraph.edgesInto(current);
            List<Edge> callerEdges = new ArrayList<>();

            while (edgesInto.hasNext()) {
                callerEdges.add(edgesInto.next());
            }

            // Case 1: No callers - we've reached a root
            if (callerEdges.isEmpty()) {
                if (verbose) {
                    System.out.println("Found root (no callers): " + current.getSignature());
                }

                // This path is complete - reverse it so it goes root -> sink
                currentPath.reverse();
                reachGraph.addCompletePath(currentPath);
                continue;
            }

            // Case 2: Has callers - extend the path backward
            if (verbose && callerEdges.size() > 1) {
                System.out.println("Branching: " + current.getName() + " has " + callerEdges.size() + " callers");
            }

            for (Edge edge : callerEdges) {
                SootMethod caller = edge.src();

                // Record caller relationship in graph
                reachGraph.addCaller(current, caller, edge);

                // Check for cycle in THIS path
                if (visitedInPath.contains(caller)) {
                    if (verbose) {
                        System.out.println("Cycle detected: " + caller.getName() + " already in path");
                    }
                    // Create path with cycle, mark it, and store
                    ExecutionPath cyclicPath = currentPath.copy("path-" + pathCounter++ + "-cyclic");
                    cyclicPath.addMethod(caller);
                    cyclicPath.addEdge(edge);
                    cyclicPath.reverse();
                    reachGraph.addCompletePath(cyclicPath);
                    continue;
                }

                // Create new path extending backward to caller
                ExecutionPath newPath = currentPath.copy("path-" + pathCounter++);
                newPath.addMethod(caller);
                newPath.addEdge(edge);

                // Create new visited set for this path
                Set<SootMethod> newVisited = new HashSet<>(visitedInPath);
                newVisited.add(caller);

                // Add to worklist
                worklist.add(new WorklistItem(caller, newPath, newVisited));
            }
        }

        if (verbose) {
            System.out.println("\n=== Analysis Complete ===");
            System.out.println("Processed " + processedCount + " worklist items");
            System.out.println(reachGraph.getStatistics());
        }

        return reachGraph;
    }

    /**
     * Complete analysis: Phase 1 (reachability) + Phase 2A (CFG construction)
     * 
     * @param sink      The sink method to analyze
     * @param buildCFGs Whether to build detailed CFGs after reachability analysis
     * @return Complete analysis result with reachability and CFGs
     */
    public CompleteAnalysisResult findPathsAndBuildCFGs(SootMethod sink, boolean buildCFGs) {
        if (verbose) {
            System.out.println("=== Starting Complete Backward Analysis ===");
            System.out.println("Sink: " + sink.getSignature());
            System.out.println("Build CFGs: " + buildCFGs);
        }

        // Phase 1: Backward reachability
        ReachabilityGraph reachGraph = findPathsToSink(sink);

        if (verbose) {
            System.out.println("\n" + reachGraph.getStatistics());
        }

        // Phase 2A: CFG construction (optional)
        MethodCFGBuilder.CFGConstructionResult cfgResult = null;
        if (buildCFGs) {
            if (verbose) {
                System.out.println("\n=== Starting Phase 2A: CFG Construction ===");
            }

            MethodCFGBuilder cfgBuilder = new MethodCFGBuilder();
            cfgBuilder.setVerbose(verbose);

            List<MethodCFGInfo> cfgInfos = cfgBuilder.buildCFGs(reachGraph);
            cfgBuilder.identifySinkLeadingCalls(cfgInfos, reachGraph);
            cfgResult = cfgBuilder.createResult(cfgInfos, reachGraph);

            if (verbose) {
                System.out.println(cfgResult.getStatistics());
            }
        }

        CompleteAnalysisResult result = new CompleteAnalysisResult(reachGraph, cfgResult);

        if (verbose) {
            System.out.println("\n=== Complete Analysis Summary ===");
            System.out.println(result.getSummary());
        }

        return result;
    }

    /**
     * Convenience method: Run complete analysis with CFG construction
     */
    public CompleteAnalysisResult findPathsAndBuildCFGs(SootMethod sink) {
        return findPathsAndBuildCFGs(sink, true);
    }

    /**
     * Helper class to store worklist items
     */
    private static class WorklistItem {
        SootMethod method;
        ExecutionPath path;
        Set<SootMethod> visitedInPath; // Methods visited in THIS specific path (for cycle detection)

        WorklistItem(SootMethod method, ExecutionPath path, Set<SootMethod> visitedInPath) {
            this.method = method;
            this.path = path;
            this.visitedInPath = visitedInPath;
        }
    }

    /**
     * Result container for complete analysis (Phase 1 + Phase 2A)
     */
    public static class CompleteAnalysisResult {
        private ReachabilityGraph reachabilityGraph;
        private MethodCFGBuilder.CFGConstructionResult cfgResult;

        public CompleteAnalysisResult(ReachabilityGraph reachabilityGraph,
                MethodCFGBuilder.CFGConstructionResult cfgResult) {
            this.reachabilityGraph = reachabilityGraph;
            this.cfgResult = cfgResult;
        }

        /**
         * Get the reachability analysis results (Phase 1)
         */
        public ReachabilityGraph getReachabilityGraph() {
            return reachabilityGraph;
        }

        /**
         * Get the CFG construction results (Phase 2A)
         */
        public MethodCFGBuilder.CFGConstructionResult getCFGResult() {
            return cfgResult;
        }

        /**
         * Check if CFG analysis was performed
         */
        public boolean hasCFGs() {
            return cfgResult != null;
        }

        /**
         * Get CFG for a specific method
         */
        public MethodCFGInfo getCFGForMethod(SootMethod method) {
            return cfgResult != null ? cfgResult.getCFGForMethod(method) : null;
        }

        /**
         * Get all method CFGs
         */
        public List<MethodCFGInfo> getAllCFGs() {
            return cfgResult != null ? cfgResult.getCFGInfos() : Collections.emptyList();
        }

        /**
         * Get complete analysis summary
         */
        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== Complete Analysis Summary ===\n");
            sb.append("Sink: ").append(reachabilityGraph.getSink().getSignature()).append("\n");
            sb.append("Reachable methods: ").append(reachabilityGraph.getReachableMethods().size()).append("\n");
            sb.append("Complete paths: ").append(reachabilityGraph.getCompletePaths().size()).append("\n");

            if (hasCFGs()) {
                sb.append("Methods with CFGs: ").append(cfgResult.getTotalMethods()).append("\n");
                sb.append("Total CFG units: ").append(cfgResult.getTotalUnits()).append("\n");

                int sinkLeadingCalls = getAllCFGs().stream()
                        .mapToInt(cfg -> cfg.getSinkLeadingCalls().size())
                        .sum();
                sb.append("Sink-leading call sites: ").append(sinkLeadingCalls).append("\n");
            } else {
                sb.append("CFG analysis: Not performed\n");
            }

            return sb.toString();
        }

        /**
         * Print detailed analysis results
         */
        public void printDetailedResults() {
            System.out.println(getSummary());

            if (hasCFGs()) {
                System.out.println("\n=== Method CFG Details ===");
                for (MethodCFGInfo cfg : getAllCFGs()) {
                    System.out.println(cfg.toString());
                    if (!cfg.getSinkLeadingCalls().isEmpty()) {
                        System.out.println("  Sink-leading calls:");
                        for (soot.Unit callSite : cfg.getSinkLeadingCalls()) {
                            System.out.println("    " + callSite);
                        }
                    }
                }
            }

            System.out.println("\n=== Execution Paths ===");
            for (ExecutionPath path : reachabilityGraph.getCompletePaths()) {
                System.out.println(path.toString());
            }
        }
    }
}