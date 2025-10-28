package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.Unit;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import java.util.*;

/**
 * Builds control flow graphs for all methods that can reach the sink.
 * Takes ReachabilityGraph from Phase 1 and produces detailed CFGs for Phase 2B
 * analysis.
 */
public class MethodCFGBuilder {

    private boolean verbose;
    private boolean includeExceptions;

    public MethodCFGBuilder() {
        this.verbose = false;
        this.includeExceptions = false; // Start with BriefUnitGraph for simplicity
    }

    /**
     * Enable/disable verbose output
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * Enable/disable exception flow in CFGs
     */
    public void setIncludeExceptions(boolean includeExceptions) {
        this.includeExceptions = includeExceptions;
    }

    /**
     * Build CFGs for all reachable methods from the reachability analysis.
     * 
     * @param reachGraph The reachability graph from Phase 1
     * @return List of MethodCFGInfo objects containing CFGs and metadata
     */
    public List<MethodCFGInfo> buildCFGs(ReachabilityGraph reachGraph) {
        if (verbose) {
            System.out.println("=== Phase 2A: Building Method CFGs ===");
            System.out.println("Total reachable methods: " + reachGraph.getReachableMethods().size());
        }

        List<MethodCFGInfo> cfgInfos = new ArrayList<>();
        Set<SootMethod> reachableMethods = reachGraph.getReachableMethods();

        int processedCount = 0;
        int skippedCount = 0;

        for (SootMethod method : reachableMethods) {
            try {
                MethodCFGInfo cfgInfo = buildSingleMethodCFG(method);
                if (cfgInfo != null) {
                    cfgInfos.add(cfgInfo);
                    processedCount++;

                    if (verbose) {
                        System.out.println("Built CFG for: " + method.getSignature());
                        System.out.println("  " + cfgInfo.toString());
                    }
                } else {
                    skippedCount++;
                    if (verbose) {
                        System.out.println("Skipped (no body): " + method.getSignature());
                    }
                }
            } catch (Exception e) {
                skippedCount++;
                if (verbose) {
                    System.out.println("Error building CFG for " + method.getSignature() + ": " + e.getMessage());
                }
            }
        }

        if (verbose) {
            System.out.println("\n=== CFG Construction Summary ===");
            System.out.println("Successfully built: " + processedCount + " CFGs");
            System.out.println("Skipped: " + skippedCount + " methods");
            System.out.println("Total CFG nodes: " + getTotalNodes(cfgInfos));
            System.out.println("Total call sites: " + getTotalCallSites(cfgInfos));
        }

        return cfgInfos;
    }

    /**
     * Build CFG for a single method
     */
    private MethodCFGInfo buildSingleMethodCFG(SootMethod method) {
        // Check if method has an active body
        if (!method.hasActiveBody()) {
            return null;
        }

        try {
            // Build unit-level CFG using Soot
            UnitGraph cfg;
            if (includeExceptions) {
                cfg = new ExceptionalUnitGraph(method.getActiveBody());
            } else {
                cfg = new BriefUnitGraph(method.getActiveBody());
            }

            // Create our wrapper with metadata
            MethodCFGInfo cfgInfo = new MethodCFGInfo(method, cfg);

            // Perform basic analysis
            analyzeCallSites(cfgInfo);

            return cfgInfo;

        } catch (Exception e) {
            if (verbose) {
                System.err.println("Failed to build CFG for " + method.getSignature() + ": " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Analyze call sites in the method CFG
     */
    private void analyzeCallSites(MethodCFGInfo cfgInfo) {
        // Find all method call sites
        for (Unit unit : cfgInfo.getUnits()) {
            if (cfgInfo.isMethodCall(unit)) {
                SootMethod calledMethod = cfgInfo.getCalledMethod(unit);
                if (calledMethod != null && verbose) {
                    System.out.println("  Call site: " + unit + " -> " + calledMethod.getName());
                }
            }
        }
    }

    /**
     * Build CFGs for a specific execution path
     * This is useful when we want to focus on specific paths from Phase 1
     */
    public List<MethodCFGInfo> buildCFGsForPath(ExecutionPath path) {
        if (verbose) {
            System.out.println("=== Building CFGs for specific path: " + path.getPathId() + " ===");
        }

        List<MethodCFGInfo> cfgInfos = new ArrayList<>();

        for (SootMethod method : path.getMethods()) {
            MethodCFGInfo cfgInfo = buildSingleMethodCFG(method);
            if (cfgInfo != null) {
                cfgInfos.add(cfgInfo);

                if (verbose) {
                    System.out.println("Built CFG for path method: " + method.getName());
                }
            }
        }

        return cfgInfos;
    }

    /**
     * Identify sink-leading call sites in CFGs based on reachability information
     */
    public void identifySinkLeadingCalls(List<MethodCFGInfo> cfgInfos, ReachabilityGraph reachGraph) {
        if (verbose) {
            System.out.println("\n=== Identifying Sink-Leading Call Sites ===");
        }

        for (MethodCFGInfo cfgInfo : cfgInfos) {
            SootMethod currentMethod = cfgInfo.getMethod();

            // Get methods that this method calls toward sink
            Set<SootMethod> callersOfCurrent = reachGraph.getCallers(currentMethod);

            // Find call sites in CFG that call toward sink
            for (Unit unit : cfgInfo.getUnits()) {
                if (cfgInfo.isMethodCall(unit)) {
                    SootMethod calledMethod = cfgInfo.getCalledMethod(unit);

                    if (calledMethod != null && reachGraph.isReachable(calledMethod)) {
                        // Check if this call is toward sink
                        if (isCallTowardSink(currentMethod, calledMethod, reachGraph)) {
                            cfgInfo.addSinkLeadingCall(unit);

                            if (verbose) {
                                System.out.println("Sink-leading call: " + currentMethod.getName() +
                                        " -> " + calledMethod.getName());
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if a call from caller to callee is toward the sink
     */
    private boolean isCallTowardSink(SootMethod caller, SootMethod callee, ReachabilityGraph reachGraph) {
        // Simple check: if callee is closer to sink than caller
        // This could be improved with more sophisticated distance calculation

        // If callee is the sink itself
        if (callee.equals(reachGraph.getSink())) {
            return true;
        }

        // If callee can reach sink and caller calls callee in reachability graph
        if (reachGraph.isReachable(callee) && reachGraph.getCallers(callee).contains(caller)) {
            return true;
        }

        return false;
    }

    /**
     * Get statistics about CFG collection
     */
    private int getTotalNodes(List<MethodCFGInfo> cfgInfos) {
        return cfgInfos.stream()
                .mapToInt(cfg -> cfg.getUnits().size())
                .sum();
    }

    private int getTotalCallSites(List<MethodCFGInfo> cfgInfos) {
        return cfgInfos.stream()
                .mapToInt(cfg -> cfg.getStatistics().callSites)
                .sum();
    }

    /**
     * Create a summary of CFG construction results
     */
    public CFGConstructionResult createResult(List<MethodCFGInfo> cfgInfos, ReachabilityGraph reachGraph) {
        return new CFGConstructionResult(cfgInfos, reachGraph);
    }

    /**
     * Results container for CFG construction
     */
    public static class CFGConstructionResult {
        private List<MethodCFGInfo> cfgInfos;
        private ReachabilityGraph reachGraph;
        private Map<SootMethod, MethodCFGInfo> methodToCFG;

        public CFGConstructionResult(List<MethodCFGInfo> cfgInfos, ReachabilityGraph reachGraph) {
            this.cfgInfos = cfgInfos;
            this.reachGraph = reachGraph;
            this.methodToCFG = new HashMap<>();

            // Build lookup map
            for (MethodCFGInfo cfg : cfgInfos) {
                methodToCFG.put(cfg.getMethod(), cfg);
            }
        }

        public List<MethodCFGInfo> getCFGInfos() {
            return Collections.unmodifiableList(cfgInfos);
        }

        public ReachabilityGraph getReachabilityGraph() {
            return reachGraph;
        }

        public MethodCFGInfo getCFGForMethod(SootMethod method) {
            return methodToCFG.get(method);
        }

        public int getTotalMethods() {
            return cfgInfos.size();
        }

        public int getTotalUnits() {
            return cfgInfos.stream().mapToInt(cfg -> cfg.getUnits().size()).sum();
        }

        public String getStatistics() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== CFG Construction Result ===\n");
            sb.append("Methods with CFGs: ").append(getTotalMethods()).append("\n");
            sb.append("Total units: ").append(getTotalUnits()).append("\n");

            int totalSinkCalls = cfgInfos.stream()
                    .mapToInt(cfg -> cfg.getSinkLeadingCalls().size())
                    .sum();
            sb.append("Sink-leading call sites: ").append(totalSinkCalls).append("\n");

            return sb.toString();
        }
    }
}