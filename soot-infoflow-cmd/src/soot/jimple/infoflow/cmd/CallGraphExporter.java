package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import com.google.gson.*;
import soot.MethodOrMethodContext;

/**
 * Standalone utility for exporting Soot call graphs to JSON and DOT formats.
 * Helps with method discovery and visualization for constraint analysis.
 */
public class CallGraphExporter {
    private final Gson gson;

    public CallGraphExporter() {
        this.gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    }

    /**
     * Export call graph to JSON format showing caller -> callees mapping
     */
    public void exportToJson(CallGraph callGraph, String filename) {
        try {
            System.out.println("Exporting call graph to JSON: " + filename);

            Map<String, List<String>> callGraphMap = new LinkedHashMap<>();

            // Get all reachable methods correctly
            Set<SootMethod> reachableMethods = new HashSet<>();
            Iterator<MethodOrMethodContext> reachableIter = Scene.v().getReachableMethods().listener();
            while (reachableIter.hasNext()) {
                reachableMethods.add(reachableIter.next().method());
            }

            // Build caller -> callees mapping
            for (SootMethod method : reachableMethods) {
                String methodSig = method.getSignature();
                List<String> callees = new ArrayList<>();

                // Get all methods this method calls
                Iterator<Edge> outEdges = callGraph.edgesOutOf(method);
                while (outEdges.hasNext()) {
                    Edge edge = outEdges.next();
                    SootMethod target = edge.tgt();
                    if (target != null) {
                        callees.add(target.getSignature());
                    }
                }

                // Sort callees for consistent output
                callees.sort(String::compareTo);
                callGraphMap.put(methodSig, callees);
            }

            // Write to file
            try (FileWriter writer = new FileWriter(filename)) {
                gson.toJson(callGraphMap, writer);
            }

            System.out.println("✅ JSON export complete: " + callGraphMap.size() + " methods exported");

        } catch (IOException e) {
            System.err.println("❌ Error exporting to JSON: " + e.getMessage());
        }
    }

    /**
     * Export call graph to DOT format for Graphviz visualization
     */
    public void exportToDot(CallGraph callGraph, String filename) {
        try {
            System.out.println("Exporting call graph to DOT: " + filename);

            try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
                writer.println("digraph CallGraph {");
                writer.println("  rankdir=TB;");
                writer.println("  node [shape=box, fontsize=10];");
                writer.println("  edge [fontsize=8];");
                writer.println();

                Set<String> writtenNodes = new HashSet<>();
                Set<String> writtenEdges = new HashSet<>();
                int edgeCount = 0;

                // Get all reachable methods correctly
                Set<SootMethod> reachableMethods = new HashSet<>();
                Iterator<MethodOrMethodContext> reachableIter = Scene.v().getReachableMethods().listener();
                while (reachableIter.hasNext()) {
                    reachableMethods.add(reachableIter.next().method());
                }

                // Process all reachable methods
                for (SootMethod method : reachableMethods) {
                    String methodSig = method.getSignature();
                    String nodeId = getNodeId(methodSig);
                    String nodeLabel = getNodeLabel(method);

                    // Write node declaration
                    if (!writtenNodes.contains(nodeId)) {
                        writer.println("  " + nodeId + " [label=\"" + escapeLabel(nodeLabel) + "\"];");
                        writtenNodes.add(nodeId);
                    }

                    // Write edges to callees
                    Iterator<Edge> outEdges = callGraph.edgesOutOf(method);
                    while (outEdges.hasNext()) {
                        Edge edge = outEdges.next();
                        SootMethod target = edge.tgt();
                        if (target != null) {
                            String targetId = getNodeId(target.getSignature());
                            String targetLabel = getNodeLabel(target);
                            String edgeKey = nodeId + " -> " + targetId;

                            // Write target node if not written
                            if (!writtenNodes.contains(targetId)) {
                                writer.println("  " + targetId + " [label=\"" + escapeLabel(targetLabel) + "\"];");
                                writtenNodes.add(targetId);
                            }

                            // Write edge if not written
                            if (!writtenEdges.contains(edgeKey)) {
                                writer.println("  " + nodeId + " -> " + targetId + ";");
                                writtenEdges.add(edgeKey);
                                edgeCount++;
                            }
                        }
                    }
                }

                writer.println("}");

                System.out.println("✅ DOT export complete: " + writtenNodes.size() + " nodes, " + edgeCount + " edges");
                System.out.println("   Visualize with: dot -Tpng " + filename + " -o callgraph.png");
            }

        } catch (IOException e) {
            System.err.println("❌ Error exporting to DOT: " + e.getMessage());
        }
    }

    /**
     * Print call graph statistics and interesting methods
     */
    public void printMethodStats(CallGraph callGraph) {
        System.out.println("\n=== CALL GRAPH STATISTICS ===");

        // Get reachable methods correctly
        Set<SootMethod> reachableMethods = new HashSet<>();
        Iterator<MethodOrMethodContext> reachableIter = Scene.v().getReachableMethods().listener();
        while (reachableIter.hasNext()) {
            reachableMethods.add(reachableIter.next().method());
        }

        System.out.println("Total reachable methods: " + reachableMethods.size());

        // Count edges correctly
        int totalEdges = 0;
        for (SootMethod method : reachableMethods) {
            Iterator<Edge> edges = callGraph.edgesOutOf(method);
            while (edges.hasNext()) {
                edges.next();
                totalEdges++;
            }
        }
        System.out.println("Total call graph edges: " + totalEdges);

        // Find interesting methods
        System.out.println("\n=== INTERESTING METHODS FOR CONSTRAINT ANALYSIS ===");

        // Methods with many callers (good targets)
        List<MethodStats> methodStats = new ArrayList<>();
        for (SootMethod method : reachableMethods) {
            if (isAppSpecific(method)) {
                // Count callers correctly
                int callerCount = 0;
                Iterator<Edge> callerIter = callGraph.edgesInto(method);
                while (callerIter.hasNext()) {
                    callerIter.next();
                    callerCount++;
                }

                // Count callees correctly
                int calleeCount = 0;
                Iterator<Edge> calleeIter = callGraph.edgesOutOf(method);
                while (calleeIter.hasNext()) {
                    calleeIter.next();
                    calleeCount++;
                }

                methodStats.add(new MethodStats(method, callerCount, calleeCount));
            }
        }

        // Sort by caller count (descending)
        methodStats.sort((a, b) -> Integer.compare(b.callerCount, a.callerCount));

        System.out.println("\nTop methods with most callers (good constraint targets):");
        methodStats.stream()
                .filter(s -> s.callerCount > 0)
                .limit(10)
                .forEach(s -> System.out.println("  " + s.callerCount + " callers: " + s.method.getSignature()));

        System.out.println("\nMethods with interesting names (UI/business logic):");
        methodStats.stream()
                .filter(s -> hasInterestingName(s.method))
                .limit(10)
                .forEach(s -> System.out.println("  " + s.method.getSignature()));

        System.out.println("===============================\n");
    }

    /**
     * Generate unique node ID for DOT format
     */
    private String getNodeId(String signature) {
        return "node" + Math.abs(signature.hashCode());
    }

    /**
     * Generate readable node label
     */
    private String getNodeLabel(SootMethod method) {
        String className = method.getDeclaringClass().getShortName();
        String methodName = method.getName();
        return className + "." + methodName;
    }

    /**
     * Escape special characters for DOT labels
     */
    private String escapeLabel(String label) {
        return label.replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\\", "\\\\");
    }

    /**
     * Check if method is app-specific (not framework/library)
     */
    private boolean isAppSpecific(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        return !className.startsWith("java.") &&
                !className.startsWith("javax.") &&
                !className.startsWith("android.") &&
                !className.startsWith("androidx.") &&
                !className.startsWith("com.google.") &&
                !className.startsWith("org.apache.");
    }

    /**
     * Check if method has interesting name for constraint analysis
     */
    private boolean hasInterestingName(SootMethod method) {
        String name = method.getName().toLowerCase();
        return name.contains("click") ||
                name.contains("save") ||
                name.contains("delete") ||
                name.contains("update") ||
                name.contains("menu") ||
                name.contains("button") ||
                name.contains("touch") ||
                name.contains("submit") ||
                name.contains("send") ||
                name.contains("create");
    }

    /**
     * Helper class for method statistics
     */
    private static class MethodStats {
        final SootMethod method;
        final int callerCount;
        final int calleeCount;

        MethodStats(SootMethod method, int callerCount, int calleeCount) {
            this.method = method;
            this.callerCount = callerCount;
            this.calleeCount = calleeCount;
        }
    }
}