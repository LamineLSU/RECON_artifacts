package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.Unit;
import java.util.*;

/**
 * Detailed CFG Structure Visualizer
 * Shows every statement in each method CFG with control flow connections.
 */
public class DetailedCFGVisualizer {

    private boolean verbose;

    public DetailedCFGVisualizer() {
        this.verbose = false;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * Main method: Visualize detailed CFG structure for all methods
     */
    public void visualizeDetailedCFGStructure(BackwardReachabilityAnalyzer.CompleteAnalysisResult result) {
        if (!result.hasCFGs()) {
            System.out.println("No CFGs available for detailed visualization");
            return;
        }

        System.out.println("=== DETAILED CFG STRUCTURE VISUALIZATION ===\n");

        // Show overview first
        showOverview(result);

        // Then show each method's detailed CFG
        for (MethodCFGInfo cfg : result.getAllCFGs()) {
            visualizeSingleMethodCFG(cfg);
        }

        showSummary(result);
    }

    /**
     * Show overview of all methods
     */
    private void showOverview(BackwardReachabilityAnalyzer.CompleteAnalysisResult result) {
        System.out.println("OVERVIEW:");
        System.out.println("Sink: " + result.getReachabilityGraph().getSink().getName());
        System.out.println("Methods with CFGs: " + result.getAllCFGs().size());

        int totalUnits = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getUnits().size()).sum();
        int totalSinkCalls = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getSinkLeadingCalls().size()).sum();

        System.out.println("Total units: " + totalUnits);
        System.out.println("Total sink-leading calls: " + totalSinkCalls);
        System.out.println();
    }

    /**
     * Visualize detailed CFG for a single method
     */
    public void visualizeSingleMethodCFG(MethodCFGInfo cfg) {
        SootMethod method = cfg.getMethod();

        System.out.println("=".repeat(80));
        System.out.println("METHOD CFG: " + method.getName());
        System.out.println("Full signature: " + method.getSignature());
        System.out.println("Class: " + method.getDeclaringClass().getName());
        System.out.println("Units: " + cfg.getUnits().size());
        System.out.println("Call sites: " + cfg.getStatistics().callSites);
        System.out.println("Branch points: " + cfg.getStatistics().branchPoints);
        System.out.println("Sink-leading calls: " + cfg.getSinkLeadingCalls().size());
        System.out.println("=".repeat(80));

        // Create unit to index mapping for easier reference
        Map<Unit, Integer> unitToIndex = new HashMap<>();
        List<Unit> unitList = new ArrayList<>(cfg.getUnits());
        for (int i = 0; i < unitList.size(); i++) {
            unitToIndex.put(unitList.get(i), i);
        }

        // Show each unit with detailed information
        System.out.println("\nCFG UNITS:");
        for (int i = 0; i < unitList.size(); i++) {
            Unit unit = unitList.get(i);
            showUnitDetails(cfg, unit, i, unitToIndex);
        }

        // Show entry and exit points
        showEntryExitPoints(cfg, unitToIndex);

        // Show sink-leading calls summary
        showSinkLeadingCallsSummary(cfg);

        System.out.println();
    }

    /**
     * Show detailed information for a single unit
     */
    private void showUnitDetails(MethodCFGInfo cfg, Unit unit, int index, Map<Unit, Integer> unitToIndex) {
        String prefix = String.format("[%3d]", index);

        // Basic unit information
        System.out.println(prefix + " " + unit);

        // Check for special properties
        List<String> properties = new ArrayList<>();

        // Check if it's a sink-leading call
        if (cfg.getSinkLeadingCalls().contains(unit)) {
            properties.add("SINK-LEADING CALL");
        }

        // Check if it's a method call
        if (cfg.isMethodCall(unit)) {
            SootMethod calledMethod = cfg.getCalledMethod(unit);
            if (calledMethod != null) {
                properties.add("CALLS: " + calledMethod.getName());
            } else {
                properties.add("METHOD CALL");
            }
        }

        // Check if it's an entry point
        if (cfg.getEntryPoints().contains(unit)) {
            properties.add("ENTRY POINT");
        }

        // Check if it's an exit point
        if (cfg.getExitPoints().contains(unit)) {
            properties.add("EXIT POINT");
        }

        // Show properties
        if (!properties.isEmpty()) {
            System.out.println("      Properties: " + String.join(", ", properties));
        }

        // Show control flow
        showControlFlow(cfg, unit, unitToIndex);

        System.out.println();
    }

    /**
     * Show control flow information for a unit
     */
    private void showControlFlow(MethodCFGInfo cfg, Unit unit, Map<Unit, Integer> unitToIndex) {
        List<Unit> successors = cfg.getSuccessors(unit);
        List<Unit> predecessors = cfg.getPredecessors(unit);

        // Show predecessors
        if (!predecessors.isEmpty() && predecessors.size() > 1) {
            System.out.println("      Predecessors (" + predecessors.size() + "):");
            for (Unit pred : predecessors) {
                Integer predIndex = unitToIndex.get(pred);
                if (predIndex != null) {
                    System.out.println("        <- [" + predIndex + "] " +
                            truncateUnit(pred.toString(), 50));
                }
            }
        }

        // Show successors
        if (successors.size() > 1) {
            // Multiple successors = branch point
            System.out.println("      BRANCH (" + successors.size() + " targets):");
            for (Unit succ : successors) {
                Integer succIndex = unitToIndex.get(succ);
                if (succIndex != null) {
                    System.out.println("        -> [" + succIndex + "] " +
                            truncateUnit(succ.toString(), 50));
                }
            }
        } else if (successors.size() == 1) {
            // Single successor
            Unit succ = successors.get(0);
            Integer succIndex = unitToIndex.get(succ);
            if (succIndex != null) {
                // Only show if it's not the next sequential unit
                Integer currentIndex = unitToIndex.get(unit);
                if (currentIndex != null && succIndex != currentIndex + 1) {
                    System.out.println("      -> GOTO [" + succIndex + "] " +
                            truncateUnit(succ.toString(), 50));
                }
            }
        } else {
            // No successors
            System.out.println("      -> END (no successors)");
        }
    }

    /**
     * Show entry and exit points
     */
    private void showEntryExitPoints(MethodCFGInfo cfg, Map<Unit, Integer> unitToIndex) {
        System.out.println("\nENTRY POINTS:");
        for (Unit entry : cfg.getEntryPoints()) {
            Integer index = unitToIndex.get(entry);
            System.out.println("  [" + index + "] " + entry);
        }

        System.out.println("\nEXIT POINTS:");
        for (Unit exit : cfg.getExitPoints()) {
            Integer index = unitToIndex.get(exit);
            System.out.println("  [" + index + "] " + exit);
        }
    }

    /**
     * Show summary of sink-leading calls for this method
     */
    private void showSinkLeadingCallsSummary(MethodCFGInfo cfg) {
        if (!cfg.getSinkLeadingCalls().isEmpty()) {
            System.out.println("\nSINK-LEADING CALLS IN THIS METHOD:");
            for (Unit callSite : cfg.getSinkLeadingCalls()) {
                SootMethod calledMethod = cfg.getCalledMethod(callSite);
                System.out.println("  " + callSite);
                if (calledMethod != null) {
                    System.out.println("    -> Calls: " + calledMethod.getSignature());
                }
            }
        }
    }

    /**
     * Show overall summary
     */
    private void showSummary(BackwardReachabilityAnalyzer.CompleteAnalysisResult result) {
        System.out.println("=".repeat(80));
        System.out.println("DETAILED CFG VISUALIZATION SUMMARY");
        System.out.println("=".repeat(80));

        // Method statistics
        System.out.println("Method-by-Method Statistics:");
        for (MethodCFGInfo cfg : result.getAllCFGs()) {
            MethodCFGInfo.CFGStatistics stats = cfg.getStatistics();
            System.out.println("  " + cfg.getMethod().getName() + ":");
            System.out.println("    Units: " + stats.totalUnits);
            System.out.println("    Call sites: " + stats.callSites);
            System.out.println("    Branch points: " + stats.branchPoints);
            System.out.println("    Sink-leading calls: " + stats.sinkLeadingCalls);
        }

        // Overall statistics
        int totalUnits = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getUnits().size()).sum();
        int totalCallSites = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getStatistics().callSites).sum();
        int totalBranches = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getStatistics().branchPoints).sum();
        int totalSinkCalls = result.getAllCFGs().stream().mapToInt(cfg -> cfg.getSinkLeadingCalls().size()).sum();

        System.out.println("\nOverall Statistics:");
        System.out.println("  Total methods: " + result.getAllCFGs().size());
        System.out.println("  Total units: " + totalUnits);
        System.out.println("  Total call sites: " + totalCallSites);
        System.out.println("  Total branch points: " + totalBranches);
        System.out.println("  Total sink-leading calls: " + totalSinkCalls);

        // Execution paths
        System.out.println("\nExecution Paths to Sink:");
        for (ExecutionPath path : result.getReachabilityGraph().getCompletePaths()) {
            System.out.println("  " + path.getPathId() + ": " + path.getLength() + " methods");
        }

        System.out.println("\nDetailed CFG visualization complete.");
    }

    /**
     * Utility method to truncate long unit strings
     */
    private String truncateUnit(String unitStr, int maxLength) {
        if (unitStr.length() <= maxLength) {
            return unitStr;
        }
        return unitStr.substring(0, maxLength - 3) + "...";
    }

    /**
     * Visualize just one specific method (useful for focused debugging)
     */
    public void visualizeSpecificMethod(BackwardReachabilityAnalyzer.CompleteAnalysisResult result, String methodName) {
        for (MethodCFGInfo cfg : result.getAllCFGs()) {
            if (cfg.getMethod().getName().equals(methodName)) {
                System.out.println("=== DETAILED CFG FOR SPECIFIC METHOD ===\n");
                visualizeSingleMethodCFG(cfg);
                return;
            }
        }
        System.out.println("Method '" + methodName + "' not found in CFG results.");
    }
}