package soot.jimple.infoflow.cmd;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class CallGraphJsonExporter {

    public static void exportToJson(String outputPath) {
        CallGraph callGraph = Scene.v().getCallGraph();
        Map<String, Set<String>> methodCallMap = new HashMap<>();

        // Process all edges in the call graph
        Iterator<Edge> edges = callGraph.iterator();
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            String srcSignature = src.getSignature();
            String tgtSignature = tgt.getSignature();

            // Add the target method to the source method's set of called methods
            methodCallMap.computeIfAbsent(srcSignature, k -> new HashSet<>())
                    .add(tgtSignature);
        }

        // Convert Set to List for each method's targets (for better JSON formatting)
        Map<String, List<String>> finalMap = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : methodCallMap.entrySet()) {
            finalMap.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }

        // Create Gson instance with pretty printing
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .create();

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(finalMap, writer);
            System.out.println("\nCall graph JSON exported to: " + outputPath);
            System.out.println("Total Methods: " + finalMap.size());
        } catch (IOException e) {
            System.err.println("Error saving call graph JSON: " + e.getMessage());
        }
    }

    public static void exportFilteredToJson(String outputPath, Set<String> packagesToInclude) {
        CallGraph callGraph = Scene.v().getCallGraph();
        Map<String, Set<String>> methodCallMap = new HashMap<>();

        // Process all edges in the call graph
        Iterator<Edge> edges = callGraph.iterator();
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            String srcSignature = src.getSignature();
            String tgtSignature = tgt.getSignature();

            // Check if either source or target method is in included packages
            boolean shouldInclude = packagesToInclude.stream()
                    .anyMatch(pkg -> srcSignature.contains(pkg) || tgtSignature.contains(pkg));

            if (shouldInclude) {
                methodCallMap.computeIfAbsent(srcSignature, k -> new HashSet<>())
                        .add(tgtSignature);
            }
        }

        // Convert Set to List for each method's targets
        Map<String, List<String>> finalMap = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : methodCallMap.entrySet()) {
            finalMap.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }

        // Create Gson instance with pretty printing
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .create();

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(finalMap, writer);
            System.out.println("\nFiltered call graph JSON exported to: " + outputPath);
            System.out.println("Total Methods: " + finalMap.size());
        } catch (IOException e) {
            System.err.println("Error saving filtered call graph JSON: " + e.getMessage());
        }
    }

    public static void exportWithStatisticsToJson(String outputPath) {
        CallGraph callGraph = Scene.v().getCallGraph();
        Map<String, Object> fullOutput = new HashMap<>();
        Map<String, Set<String>> methodCallMap = new HashMap<>();
        Map<String, Integer> statistics = new HashMap<>();

        // Process all edges
        Iterator<Edge> edges = callGraph.iterator();
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod src = edge.src();
            SootMethod tgt = edge.tgt();

            String srcSignature = src.getSignature();
            String tgtSignature = tgt.getSignature();

            methodCallMap.computeIfAbsent(srcSignature, k -> new HashSet<>())
                    .add(tgtSignature);
        }

        // Compute statistics
        statistics.put("totalMethods", methodCallMap.size());
        statistics.put("totalCalls", methodCallMap.values().stream()
                .mapToInt(Set::size).sum());

        // Convert call graph to final format
        Map<String, List<String>> callGraph2 = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : methodCallMap.entrySet()) {
            callGraph2.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }

        // Build final output
        fullOutput.put("statistics", statistics);
        fullOutput.put("callGraph", callGraph2);

        // Create Gson instance with pretty printing
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .create();

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(fullOutput, writer);
            System.out.println("\nCall graph with statistics JSON exported to: " + outputPath);
            System.out.println("Total Methods: " + statistics.get("totalMethods"));
            System.out.println("Total Calls: " + statistics.get("totalCalls"));
        } catch (IOException e) {
            System.err.println("Error saving call graph JSON: " + e.getMessage());
        }
    }
}