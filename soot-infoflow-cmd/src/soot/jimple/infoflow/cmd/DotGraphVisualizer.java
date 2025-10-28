package soot.jimple.infoflow.cmd;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

/**
 * Creates DOT graph visualization of the app-level CFG
 */
public class DotGraphVisualizer {

    private final Map<String, AppLevelCFGBuilder.AppCFGNode> appCFGNodes;
    private final Set<String> processedNodes;

    public DotGraphVisualizer(Map<String, AppLevelCFGBuilder.AppCFGNode> appCFGNodes,
            Set<String> processedNodes) {
        this.appCFGNodes = appCFGNodes;
        this.processedNodes = processedNodes;
    }

    /**
     * Generate DOT file for the app-level CFG
     */
    public void generateDotFile(String filename) {
        try {
            String dotContent = generateDotContent();

            // Write to file
            try (FileWriter writer = new FileWriter(filename)) {
                writer.write(dotContent);
            }

            System.out.println("DOT file generated: " + filename);
            System.out.println("View online at: https://dreampuf.github.io/GraphvizOnline/");
            System.out.println("Or use: dot -Tpng " + filename + " -o graph.png");

        } catch (IOException e) {
            System.err.println("Error generating DOT file: " + e.getMessage());
        }
    }

    /**
     * Generate DOT file content
     */
    private String generateDotContent() {
        StringBuilder dot = new StringBuilder();

        // DOT header
        dot.append("digraph AppCFG {\n");
        dot.append("  rankdir=TB;\n");
        dot.append("  node [shape=box, fontname=\"Arial\", fontsize=10];\n");
        dot.append("  edge [fontname=\"Arial\", fontsize=8];\n\n");

        // Group nodes by method
        Map<String, List<AppLevelCFGBuilder.AppCFGNode>> nodesByMethod = groupNodesByMethod();

        // Create subgraphs for each method
        for (Map.Entry<String, List<AppLevelCFGBuilder.AppCFGNode>> entry : nodesByMethod.entrySet()) {
            String methodName = entry.getKey();
            List<AppLevelCFGBuilder.AppCFGNode> nodes = entry.getValue();

            createMethodSubgraph(dot, methodName, nodes);
        }

        // Add all edges
        addAllEdges(dot);

        // DOT footer
        dot.append("}\n");

        return dot.toString();
    }

    /**
     * Group nodes by method name
     */
    private Map<String, List<AppLevelCFGBuilder.AppCFGNode>> groupNodesByMethod() {
        Map<String, List<AppLevelCFGBuilder.AppCFGNode>> nodesByMethod = new LinkedHashMap<>();

        for (AppLevelCFGBuilder.AppCFGNode node : appCFGNodes.values()) {
            if (processedNodes.contains(node.nodeId)) {
                String methodName = node.method.getName();
                nodesByMethod.computeIfAbsent(methodName, k -> new ArrayList<>()).add(node);
            }
        }

        // Sort nodes within each method by block index
        for (List<AppLevelCFGBuilder.AppCFGNode> nodes : nodesByMethod.values()) {
            nodes.sort(Comparator.comparingInt(n -> n.block.sootIndex));
        }

        return nodesByMethod;
    }

    /**
     * Create subgraph for a method
     */
    private void createMethodSubgraph(StringBuilder dot, String methodName,
            List<AppLevelCFGBuilder.AppCFGNode> nodes) {
        String sanitizedMethodName = sanitizeForDot(methodName);

        dot.append("  subgraph cluster_").append(sanitizedMethodName).append(" {\n");
        dot.append("    label=\"").append(methodName).append("\";\n");
        dot.append("    style=filled;\n");
        dot.append("    fillcolor=lightgray;\n");
        dot.append("    fontsize=12;\n");
        dot.append("    fontname=\"Arial Bold\";\n\n");

        // Add nodes in this method
        for (AppLevelCFGBuilder.AppCFGNode node : nodes) {
            String nodeId = getShortNodeId(node);
            String label = createNodeLabel(node);
            String nodeStyle = getNodeStyle(node);

            dot.append("    \"").append(nodeId).append("\" [label=\"").append(label)
                    .append("\"").append(nodeStyle).append("];\n");
        }

        dot.append("  }\n\n");
    }

    /**
     * Create node label with statements
     */
    private String createNodeLabel(AppLevelCFGBuilder.AppCFGNode node) {
        StringBuilder label = new StringBuilder();

        // Block header
        label.append("Block ").append(node.block.sootIndex).append("\\n");
        label.append("---\\n");

        // Add first few statements
        List<String> statements = node.block.getStatements();
        int maxStatements = 3; // Limit for readability

        for (int i = 0; i < Math.min(statements.size(), maxStatements); i++) {
            String stmt = statements.get(i);
            String shortStmt = shortenStatement(stmt);
            label.append(shortStmt).append("\\n");
        }

        if (statements.size() > maxStatements) {
            label.append("... (").append(statements.size() - maxStatements).append(" more)\\n");
        }

        return escapeForDot(label.toString());
    }

    /**
     * Shorten statement for display
     */
    private String shortenStatement(String statement) {
        // Remove package names for readability
        String shortened = statement.replaceAll("com\\.example\\.userroleselector\\.", "");

        // Truncate very long statements
        if (shortened.length() > 40) {
            shortened = shortened.substring(0, 37) + "...";
        }

        return shortened;
    }

    /**
     * Get node styling based on type
     */
    private String getNodeStyle(AppLevelCFGBuilder.AppCFGNode node) {
        // Different colors for different methods
        String methodName = node.method.getName();
        String fillColor;

        switch (methodName) {
            case "onClick":
                fillColor = "lightblue";
                break;
            case "handleAdmin":
                fillColor = "lightcoral";
                break;
            case "handleStudent":
                fillColor = "lightgreen";
                break;
            case "handleGuest":
                fillColor = "lightyellow";
                break;
            default:
                fillColor = "white";
        }

        return ", style=filled, fillcolor=" + fillColor;
    }

    /**
     * Add all edges to the DOT graph
     */
    private void addAllEdges(StringBuilder dot) {
        dot.append("  // Edges\n");

        for (AppLevelCFGBuilder.AppCFGNode node : appCFGNodes.values()) {
            if (!processedNodes.contains(node.nodeId)) {
                continue;
            }

            String fromId = getShortNodeId(node);

            // Successor edges (blue)
            for (String successor : node.successors) {
                String toId = getShortNodeId(successor);
                dot.append("  \"").append(fromId).append("\" -> \"").append(toId)
                        .append("\" [color=blue, label=\"succ\"];\n");
            }

            // Call edges (red, bold)
            for (String callTarget : node.callEdges) {
                String toId = getShortNodeId(callTarget);
                dot.append("  \"").append(fromId).append("\" -> \"").append(toId)
                        .append("\" [color=red, style=bold, penwidth=2, label=\"CALL\"];\n");
            }

            // Return edges (green, dashed)
            for (String returnTarget : node.returnEdges) {
                String toId = getShortNodeId(returnTarget);
                dot.append("  \"").append(fromId).append("\" -> \"").append(toId)
                        .append("\" [color=green, style=dashed, label=\"RETURN\"];\n");
            }
        }

        dot.append("\n");

        // Add legend
        addLegend(dot);
    }

    /**
     * Add legend to the graph
     */
    private void addLegend(StringBuilder dot) {
        dot.append("  // Legend\n");
        dot.append("  subgraph cluster_legend {\n");
        dot.append("    label=\"Legend\";\n");
        dot.append("    style=filled;\n");
        dot.append("    fillcolor=white;\n");
        dot.append("    rankdir=LR;\n");
        dot.append("    \n");
        dot.append("    legend_succ [label=\"Successor\", shape=plaintext];\n");
        dot.append("    legend_call [label=\"Method Call\", shape=plaintext];\n");
        dot.append("    legend_return [label=\"Return\", shape=plaintext];\n");
        dot.append("    \n");
        dot.append("    legend_succ -> legend_call [color=blue, label=\"succ\"];\n");
        dot.append("    legend_call -> legend_return [color=red, style=bold, label=\"CALL\"];\n");
        dot.append("    legend_return -> legend_succ [color=green, style=dashed, label=\"RETURN\"];\n");
        dot.append("  }\n");
    }

    /**
     * Get shortened node ID for DOT
     */
    private String getShortNodeId(AppLevelCFGBuilder.AppCFGNode node) {
        return node.method.getName() + "_" + node.block.sootIndex;
    }

    /**
     * Get shortened node ID from full node ID
     */
    private String getShortNodeId(String fullNodeId) {
        if (fullNodeId.contains("_block_")) {
            String[] parts = fullNodeId.split("_block_");
            if (parts.length == 2) {
                String methodName = extractMethodName(parts[0]);
                return methodName + "_" + parts[1];
            }
        }
        return fullNodeId;
    }

    /**
     * Extract method name from signature
     */
    private String extractMethodName(String signature) {
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
     * Sanitize string for DOT format
     */
    private String sanitizeForDot(String input) {
        return input.replaceAll("[^a-zA-Z0-9_]", "_");
    }

    /**
     * Escape string for DOT labels
     */
    private String escapeForDot(String input) {
        return input.replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("<", "\\<")
                .replace(">", "\\>");
    }
}