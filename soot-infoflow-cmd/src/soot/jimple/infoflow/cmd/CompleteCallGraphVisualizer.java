package soot.jimple.infoflow.cmd;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class CompleteCallGraphVisualizer {
    public static void visualizeComplete(String outputPath) {
        CallGraph callGraph = Scene.v().getCallGraph();
        Set<String> processedEdges = new HashSet<>();
        Set<String> processedNodes = new HashSet<>();

        StringBuilder dot = new StringBuilder();
        dot.append("digraph CallGraph {\n");
        dot.append("  node [shape=box,style=filled,fillcolor=lightgray];\n");

        // Iterate through all edges in the call graph
        Iterator<Edge> edges = callGraph.iterator();
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            String srcName = formatMethodName(src);
            String tgtName = formatMethodName(tgt);

            // Add source node if not processed
            if (!processedNodes.contains(srcName)) {
                dot.append(String.format("  \"%s\" [fillcolor=%s];\n",
                        srcName, getNodeColor(src)));
                processedNodes.add(srcName);
            }

            // Add target node if not processed
            if (!processedNodes.contains(tgtName)) {
                dot.append(String.format("  \"%s\" [fillcolor=%s];\n",
                        tgtName, getNodeColor(tgt)));
                processedNodes.add(tgtName);
            }

            // Add edge if not processed
            String edgeKey = srcName + "->" + tgtName;
            if (!processedEdges.contains(edgeKey)) {
                dot.append(String.format("  \"%s\" -> \"%s\";\n", srcName, tgtName));
                processedEdges.add(edgeKey);
            }
        }

        dot.append("\n  // Graph Statistics\n");
        dot.append("  label=\"Call Graph Statistics:\\n");
        dot.append("Total Methods: " + processedNodes.size() + "\\n");
        dot.append("Total Calls: " + processedEdges.size() + "\";\n");
        dot.append("  labelloc=\"t\";\n"); // Place label at top

        dot.append("}\n");

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(dot.toString());
            System.out.println("\nCall graph visualization saved to: " + outputPath);
            System.out.println("Total Methods: " + processedNodes.size());
            System.out.println("Total Calls: " + processedEdges.size());
        } catch (IOException e) {
            System.err.println("Error saving call graph visualization: " + e.getMessage());
        }
    }

    private static String formatMethodName(SootMethod method) {
        String className = method.getDeclaringClass().getShortName();
        if (className.isEmpty()) {
            className = method.getDeclaringClass().getName();
        }
        return className + "." + method.getName();
    }

    private static String getNodeColor(SootMethod method) {
        if (method.getName().equals("onCreate")) {
            return "lightblue";
        } else if (method.getName().contains("onClick") ||
                method.getName().contains("lambda")) {
            return "lightgreen";
        } else if (method.isConstructor()) {
            return "lightyellow";
        } else if (method.getDeclaringClass().getName().startsWith("android.")) {
            return "lightpink"; // Android framework methods
        }
        return "lightgray";
    }
}