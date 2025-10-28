package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.SootClass;
import soot.jimple.InvokeExpr;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;
import java.io.*;

public class CompleteAllocationGraph {
    private final Map<String, AllocationNode> nodes;
    private final Map<String, Set<EdgeInfo>> edges;
    private final AllocationGraphAnalyzer analyzer;
    private final Set<String> processedMethods;
    private final Map<String, String> dummyToComponent; // Track dummy to component relationships

    public static class EdgeInfo {
        public final String fromId;
        public final String toId;
        public final EdgeType type;

        public EdgeInfo(String fromId, String toId, EdgeType type) {
            this.fromId = fromId;
            this.toId = toId;
            this.type = type;
        }
    }

    public enum EdgeType {
        NORMAL, // Regular control flow
        METHOD_CALL, // Method invocation
        ACTIVITY_TRANSITION, // Activity transition
        THREAD_SPAWN, // Thread creation
        THREAD_COMPLETE, // Thread completion
        DUMMY_TO_COMPONENT, // Dummy method to component dummy
        COMPONENT_TO_ENTRY // Component dummy to real method
    }

    public CompleteAllocationGraph(AllocationGraphAnalyzer analyzer) {
        this.nodes = new HashMap<>();
        this.edges = new HashMap<>();
        this.analyzer = analyzer;
        this.processedMethods = new HashSet<>();
        this.dummyToComponent = new HashMap<>();
        buildDummyHierarchy();
        buildCompleteGraph();
    }

    private void buildDummyHierarchy() {
        // Create DummyMain node
        SootMethod dummyMain = analyzer.getDummyMainMethod();
        String dummyMainId = "DummyMain";
        createDummyNode(dummyMainId, dummyMain);

        // Process edges from DummyMain
        Iterator<Edge> edges = analyzer.getCallGraph().edgesOutOf(dummyMain);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod target = edge.tgt();

            if (target.getName().contains("dummyMainMethod_")) {
                // Create component dummy node
                String componentName = target.getName().substring(target.getName().indexOf('_') + 1);
                String dummyId = "Dummy_" + componentName;
                createDummyNode(dummyId, target);

                // Connect DummyMain to component dummy
                addDummyEdge(dummyMainId, dummyId, EdgeType.DUMMY_TO_COMPONENT);

                // Store relationship for later use
                dummyToComponent.put(dummyId, componentName);

                // Find and connect to real component methods
                connectComponentDummyToMethods(dummyId, target);
            }
        }
    }

    private void createDummyNode(String id, SootMethod method) {
        StringBuilder label = new StringBuilder();
        label.append(method.getName()).append("\n")
                .append(method.getDeclaringClass().getName()).append("\n")
                .append(method.getSubSignature());

        String nodeId = sanitizeNodeId(id);
        nodes.put(nodeId, null); // We don't need actual AllocationNode for dummies
        edges.putIfAbsent(nodeId, new HashSet<>());
    }

    private void connectComponentDummyToMethods(String dummyId, SootMethod dummyMethod) {
        Iterator<Edge> edges = analyzer.getCallGraph().edgesOutOf(dummyMethod);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod target = edge.tgt();

            // Only connect to real methods (not dummy methods)
            if (!target.getName().contains("dummyMainMethod") && target.hasActiveBody()) {
                AllocationGraph targetGraph = analyzer.getOrCreateMethodGraph(target);
                if (targetGraph != null && targetGraph.getEntryNode() != null) {
                    String methodId = getNodeId(target.getName(), targetGraph.getEntryNode());
                    addDummyEdge(dummyId, methodId, EdgeType.COMPONENT_TO_ENTRY);
                }
            }
        }
    }

    private void addDummyEdge(String fromId, String toId, EdgeType type) {
        edges.get(sanitizeNodeId(fromId)).add(
                new EdgeInfo(sanitizeNodeId(fromId), sanitizeNodeId(toId), type));
    }

    private void buildCompleteGraph() {
        // Process all method graphs
        for (Map.Entry<SootMethod, AllocationGraph> entry : analyzer.getMethodGraphs().entrySet()) {
            if (!entry.getKey().getName().contains("dummyMainMethod")) {
                processGraph(entry.getValue());
            }
        }

        // Connect all edges
        connectGraphEdges();
    }

    private void processGraph(AllocationGraph graph) {
        if (graph == null)
            return;

        String methodName = sanitizeMethodName(graph.getMethod().getName());

        // Add all nodes from the graph
        for (AllocationNode node : graph.getNodes()) {
            String nodeId = getNodeId(methodName, node);
            nodes.put(nodeId, node);
            edges.putIfAbsent(nodeId, new HashSet<>());
        }
    }

    private void connectGraphEdges() {
        // Process each node's successors
        for (Map.Entry<String, AllocationNode> entry : nodes.entrySet()) {
            AllocationNode node = entry.getValue();
            if (node == null)
                continue; // Skip dummy nodes

            String nodeId = entry.getKey();
            String methodName = sanitizeMethodName(node.getMethod().getName());

            for (AllocationNode successor : node.getSuccessors()) {
                String succMethodName = sanitizeMethodName(successor.getMethod().getName());
                String succId = getNodeId(succMethodName, successor);
                EdgeType type = determineEdgeType(node, successor);
                edges.get(nodeId).add(new EdgeInfo(nodeId, succId, type));
            }
        }
    }

    private EdgeType determineEdgeType(AllocationNode source, AllocationNode target) {
        if (source.getType() == NodeType.ACTIVITY_TRANSITION) {
            if (source.getTargetClass() != null &&
                    target.getType() == NodeType.ENTRY &&
                    target.getMethod().getDeclaringClass().equals(source.getTargetClass())) {
                return EdgeType.ACTIVITY_TRANSITION;
            }
        } else if (source.getType() == NodeType.THREAD_SPAWN) {
            return EdgeType.THREAD_SPAWN;
        } else if (source.getType() == NodeType.THREAD_COMPLETE) {
            return EdgeType.THREAD_COMPLETE;
        } else if (source.getType() == NodeType.METHOD_CALL) {
            return EdgeType.METHOD_CALL;
        }
        return EdgeType.NORMAL;
    }

    public void visualizeGraph(String outputPath, String format) {
        switch (format.toLowerCase()) {
            case "dot":
                generateDotFile(outputPath + ".dot");
                break;
            case "gephi":
                generateGephiFile(outputPath + ".gexf");
                break;
            case "both":
                generateDotFile(outputPath + ".dot");
                generateGephiFile(outputPath + ".gexf");
                break;
        }
    }

    public void generateDotFile(String outputPath) {
        StringBuilder dot = new StringBuilder();
        dot.append("digraph AllocationGraph {\n");
        dot.append("  rankdir=TB;\n");
        dot.append("  node [shape=box];\n\n");

        // Add dummy nodes at top level
        dot.append("  // Dummy Method Hierarchy\n");
        dot.append("  subgraph cluster_dummy {\n");
        dot.append("    label=\"Dummy Methods\";\n");
        dot.append("    style=filled;\n");
        dot.append("    color=lightgrey;\n");

        for (String nodeId : nodes.keySet()) {
            if (nodeId.startsWith("Dummy") || nodeId.equals("DummyMain")) {
                dot.append(String.format("    \"%s\" %s [label=\"%s\"];\n",
                        nodeId, getDummyNodeStyle(nodeId), getDummyNodeLabel(nodeId)));
            }
        }
        dot.append("  }\n\n");

        // Group remaining nodes by method
        Map<String, List<String>> methodToNodes = new HashMap<>();
        for (String nodeId : nodes.keySet()) {
            if (!nodeId.startsWith("Dummy") && !nodeId.equals("DummyMain")) {
                String methodName = nodeId.substring(0, nodeId.indexOf("__"));
                methodToNodes.computeIfAbsent(methodName, k -> new ArrayList<>()).add(nodeId);
            }
        }

        // Add method nodes
        for (Map.Entry<String, List<String>> entry : methodToNodes.entrySet()) {
            String method = entry.getKey();
            String sanitizedMethod = sanitizeMethodName(method);

            dot.append("  subgraph cluster_").append(sanitizedMethod).append(" {\n");
            dot.append("    label=\"").append(method).append("\";\n");

            for (String nodeId : entry.getValue()) {
                AllocationNode node = nodes.get(nodeId);
                if (node != null) {
                    String nodeStyle = getNodeStyle(node);
                    String nodeLabel = getNodeLabel(node);
                    String sanitizedNodeId = sanitizeNodeId(nodeId);
                    dot.append(String.format("    \"%s\" %s [label=\"%s\"];\n",
                            sanitizedNodeId, nodeStyle, nodeLabel));
                }
            }
            dot.append("  }\n\n");
        }

        // Add all edges
        dot.append("\n  // Edges\n");
        for (Map.Entry<String, Set<EdgeInfo>> entry : edges.entrySet()) {
            String sanitizedFromId = sanitizeNodeId(entry.getKey());
            for (EdgeInfo edge : entry.getValue()) {
                String sanitizedToId = sanitizeNodeId(edge.toId);
                String edgeStyle = getEdgeStyle(edge.type);
                dot.append(String.format("  \"%s\" -> \"%s\" %s;\n",
                        sanitizedFromId, sanitizedToId, edgeStyle));
            }
        }

        dot.append("}\n");

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(dot.toString());
            System.out.println("Graph visualization saved to: " + outputPath);
            System.out.println("Full absolute path: " + new File(outputPath).getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error saving graph visualization: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void generateGephiFile(String outputPath) {
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            writer.write("<gexf xmlns=\"http://www.gexf.net/1.2draft\" version=\"1.2\">\n");
            writer.write("  <graph mode=\"static\" defaultedgetype=\"directed\">\n");

            // Write nodes
            writer.write("    <nodes>\n");
            for (Map.Entry<String, AllocationNode> entry : nodes.entrySet()) {
                String nodeId = sanitizeNodeId(entry.getKey());
                String label = entry.getValue() != null ? getNodeLabel(entry.getValue())
                        : getDummyNodeLabel(entry.getKey());
                String nodeType = entry.getValue() != null ? entry.getValue().getType().toString() : "DUMMY";

                writer.write(String.format("      <node id=\"%s\" label=\"%s\">\n", nodeId, escapeXml(label)));
                writer.write(String.format("        <attvalues>\n"));
                writer.write(String.format("          <attvalue for=\"type\" value=\"%s\"/>\n", nodeType));
                writer.write(String.format("        </attvalues>\n"));
                writer.write("      </node>\n");
            }
            writer.write("    </nodes>\n");

            // Write edges
            writer.write("    <edges>\n");
            int edgeId = 0;
            for (Map.Entry<String, Set<EdgeInfo>> entry : edges.entrySet()) {
                for (EdgeInfo edge : entry.getValue()) {
                    writer.write(String.format("      <edge id=\"%d\" source=\"%s\" target=\"%s\" type=\"%s\"/>\n",
                            edgeId++,
                            sanitizeNodeId(edge.fromId),
                            sanitizeNodeId(edge.toId),
                            edge.type));
                }
            }
            writer.write("    </edges>\n");

            writer.write("  </graph>\n");
            writer.write("</gexf>");

            System.out.println("Gephi visualization saved to: " + outputPath);

        } catch (IOException e) {
            System.err.println("Error saving Gephi visualization: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String escapeXml(String input) {
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private String getDummyNodeStyle(String nodeId) {
        if (nodeId.equals("DummyMain")) {
            return "[shape=doubleoctagon,style=filled,fillcolor=gold]";
        }
        return "[shape=octagon,style=filled,fillcolor=lightblue]";
    }

    private String getDummyNodeLabel(String nodeId) {
        if (nodeId.equals("DummyMain")) {
            return "DummyMainMethod";
        }
        return dummyToComponent.getOrDefault(nodeId, nodeId);
    }

    private String getNodeId(String methodName, AllocationNode node) {
        return String.format("%s__%s__%s",
                sanitizeMethodName(methodName),
                sanitizeMethodName(node.getMethod().getSignature()),
                node.getId());
    }

    private String getNodeStyle(AllocationNode node) {
        switch (node.getType()) {
            case ENTRY:
                return "[shape=oval,color=green]";
            case EXIT:
                return "[shape=oval,color=red]";
            case ALLOCATION:
                return "[shape=box,color=blue]";
            case METHOD_CALL:
                return "[shape=box,color=purple]";
            case THREAD_SPAWN:
                return "[shape=hexagon,color=orange]";
            case THREAD_COMPLETE:
                return "[shape=hexagon,color=orange,style=dashed]";
            case ACTIVITY_TRANSITION:
                return "[shape=diamond,color=red]";
            case IF_CONDITION:
            case SWITCH:
                return "[shape=diamond,color=orange]";
            default:
                return "[shape=box]";
        }
    }

    private String getNodeLabel(AllocationNode node) {
        StringBuilder label = new StringBuilder();

        switch (node.getType()) {
            case ENTRY:
            case EXIT:
                label.append(node.getType()).append("\n")
                        .append(node.getMethod().getDeclaringClass().getName()).append("\n")
                        .append(node.getMethod().getName());
                break;
            case ALLOCATION:
                label.append("Alloc: ").append(node.getAllocationTypeName());
                break;
            case METHOD_CALL:
                InvokeExpr invoke = node.getMethodCall();
                if (invoke != null) {
                    label.append("Call: ").append(invoke.getMethod().getName());
                } else {
                    label.append("Method Call");
                }
                break;
            case ACTIVITY_TRANSITION:
                label.append("Activity Transition");
                if (node.getTargetClass() != null) {
                    label.append("\nTo: ").append(node.getTargetClass().getName())
                            .append("\nMethod: onCreate");
                }
                break;
            case THREAD_SPAWN:
                label.append("Thread Spawn");
                if (node.getTargetMethod() != null) {
                    label.append(": ").append(node.getTargetMethod().getName());
                }
                break;
            case THREAD_COMPLETE:
                label.append("Thread Complete");
                break;
            default:
                label.append(node.getType());
        }

        return escapeLabel(label.toString());
    }

    private String getEdgeStyle(EdgeType type) {
        switch (type) {
            case DUMMY_TO_COMPONENT:
                return "[color=blue,style=bold,penwidth=2.0]";
            case COMPONENT_TO_ENTRY:
                return "[color=green,style=dashed,penwidth=1.5]";
            case ACTIVITY_TRANSITION:
                return "[color=red,style=bold,penwidth=2.0]";
            case METHOD_CALL:
                return "[color=purple]";
            case THREAD_SPAWN:
                return "[color=orange,style=dashed]";
            case THREAD_COMPLETE:
                return "[color=orange,style=dotted]";
            default:
                return "";
        }
    }

    private String sanitizeMethodName(String name) {
        return name.replace("<", "")
                .replace(">", "")
                .replace("$", "_")
                .replace(".", "_")
                .replace(",", "_")
                .replace(" ", "_")
                .replace("(", "_")
                .replace(")", "_")
                .replace("[", "_")
                .replace("]", "_")
                .replace("-", "_")
                .replace(":", "_")
                .replace("/", "_")
                .replace("'", "")
                .replace("\"", "");
    }

    private String sanitizeNodeId(String nodeId) {
        return sanitizeMethodName(nodeId);
    }

    private String escapeLabel(String label) {
        return label.replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("<", "\\<")
                .replace(">", "\\>");
    }

    // Getters
    public Map<String, AllocationNode> getNodes() {
        return Collections.unmodifiableMap(nodes);
    }

    public Map<String, Set<EdgeInfo>> getEdges() {
        return Collections.unmodifiableMap(edges);
    }

    public Map<String, String> getDummyToComponent() {
        return Collections.unmodifiableMap(dummyToComponent);
    }
}