package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enhanced AllocationGraph that tracks object allocations and control flow
 * within a method.
 * Now includes comprehensive backward traversal support for step-by-step
 * constraint analysis.
 * Maintains all existing functionality while adding new capabilities for any
 * target method.
 */
public class AllocationGraph {
    private final String methodSignature;
    private final SootMethod method;
    private final AllocationGraphAnalyzer analyzer;
    private final Set<AllocationNode> nodes;
    private final Map<NodeType, Set<AllocationNode>> nodesByType;
    private final Map<String, AllocationNode> nodeById;
    private final Set<AllocationNode> entryNodes;
    private final Set<AllocationNode> exitNodes;

    // New: Enhanced indexing for efficient backward traversal
    private final Map<AllocationNode, Set<AllocationNode>> predecessorMap;
    private final Map<AllocationNode, Set<AllocationNode>> successorMap;
    private final Map<SootMethod, Set<AllocationNode>> methodCallMap;

    public AllocationGraph(String methodSignature, AllocationGraphAnalyzer analyzer) {
        this.methodSignature = methodSignature;
        this.analyzer = analyzer;
        this.nodes = new HashSet<>();
        this.nodesByType = new HashMap<>();
        this.nodeById = new HashMap<>();
        this.entryNodes = new HashSet<>();
        this.exitNodes = new HashSet<>();

        // Initialize new data structures
        this.predecessorMap = new HashMap<>();
        this.successorMap = new HashMap<>();
        this.methodCallMap = new HashMap<>();

        // Initialize node type map
        for (NodeType type : NodeType.values()) {
            nodesByType.put(type, new HashSet<>());
        }

        // Extract method from signature
        this.method = extractMethodFromSignature(methodSignature);

        if (method != null && method.hasActiveBody()) {
            buildGraph();
        }
    }

    /**
     * Build the allocation graph from method body (existing functionality)
     */
    private void buildGraph() {
        if (method == null || !method.hasActiveBody()) {
            return;
        }

        Body body = method.getActiveBody();

        // Create entry node
        AllocationNode entryNode = createNode("entry_" + method.getName(), NodeType.ENTRY, null, null);
        entryNodes.add(entryNode);

        AllocationNode previousNode = entryNode;

        // Process each unit in the method body
        for (Unit unit : body.getUnits()) {
            AllocationNode currentNode = processUnit(unit);

            if (currentNode != null) {
                // Connect to previous node
                if (previousNode != null) {
                    addEdge(previousNode, currentNode);
                }
                previousNode = currentNode;
            }
        }

        // Create exit node
        AllocationNode exitNode = createNode("exit_" + method.getName(), NodeType.EXIT, null, null);
        if (previousNode != null) {
            addEdge(previousNode, exitNode);
        }
        exitNodes.add(exitNode);

        // Build additional indexes
        buildIndexes();
    }

    /**
     * Process a single unit and create appropriate node
     */
    private AllocationNode processUnit(Unit unit) {
        AllocationNode node = null;

        if (unit instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) unit;
            Value rightOp = assignStmt.getRightOp();

            if (rightOp instanceof NewExpr || rightOp instanceof NewArrayExpr || rightOp instanceof NewMultiArrayExpr) {
                // Allocation node
                String nodeId = "alloc_" + nodes.size();
                node = createNode(nodeId, NodeType.ALLOCATION, unit, rightOp);
            } else if (rightOp instanceof InvokeExpr) {
                // Method call node
                String nodeId = "call_" + nodes.size();
                node = createNode(nodeId, NodeType.METHOD_CALL, unit, rightOp);

                // Index method call
                InvokeExpr invoke = (InvokeExpr) rightOp;
                methodCallMap.computeIfAbsent(invoke.getMethod(), k -> new HashSet<>()).add(node);
            }
        } else if (unit instanceof InvokeStmt) {
            // Method call node
            InvokeStmt invokeStmt = (InvokeStmt) unit;
            String nodeId = "call_" + nodes.size();
            node = createNode(nodeId, NodeType.METHOD_CALL, unit, invokeStmt.getInvokeExpr());

            // Index method call
            methodCallMap.computeIfAbsent(invokeStmt.getInvokeExpr().getMethod(), k -> new HashSet<>()).add(node);

        } else if (unit instanceof IfStmt) {
            // Conditional node
            String nodeId = "if_" + nodes.size();
            node = createNode(nodeId, NodeType.IF_CONDITION, unit, ((IfStmt) unit).getCondition());

        } else if (unit instanceof TableSwitchStmt || unit instanceof LookupSwitchStmt) {
            // Switch node
            String nodeId = "switch_" + nodes.size();
            node = createNode(nodeId, NodeType.SWITCH, unit, null);
        }

        return node;
    }

    /**
     * Create a new node and add it to the graph
     */
    private AllocationNode createNode(String id, NodeType type, Unit unit, Value value) {
        AllocationNode node = new AllocationNode(id, type, unit, method, value);
        addNode(node);
        return node;
    }

    /**
     * Add a node to the graph
     */
    public void addNode(AllocationNode node) {
        if (node == null)
            return;

        nodes.add(node);
        nodesByType.get(node.getType()).add(node);
        nodeById.put(node.getId(), node);

        // Initialize relationship maps
        predecessorMap.put(node, new HashSet<>());
        successorMap.put(node, new HashSet<>());
    }

    /**
     * Add an edge between two nodes
     */
    public void addEdge(AllocationNode from, AllocationNode to) {
        if (from == null || to == null)
            return;

        from.addSuccessor(to);

        // Update internal maps
        successorMap.computeIfAbsent(from, k -> new HashSet<>()).add(to);
        predecessorMap.computeIfAbsent(to, k -> new HashSet<>()).add(from);
    }

    /**
     * Build additional indexes for efficient querying
     */
    private void buildIndexes() {
        // Update predecessor/successor maps based on node relationships
        for (AllocationNode node : nodes) {
            Set<AllocationNode> successors = node.getSuccessors();
            successorMap.put(node, new HashSet<>(successors));

            for (AllocationNode successor : successors) {
                predecessorMap.computeIfAbsent(successor, k -> new HashSet<>()).add(node);
            }
        }
    }

    // ===== NEW METHODS FOR STEP-BY-STEP TARGETING =====

    /**
     * Get all predecessor nodes of a given node
     */
    public Set<AllocationNode> getPredecessors(AllocationNode node) {
        if (node == null)
            return new HashSet<>();
        return new HashSet<>(predecessorMap.getOrDefault(node, new HashSet<>()));
    }

    /**
     * Get all successor nodes of a given node
     */
    public Set<AllocationNode> getSuccessors(AllocationNode node) {
        if (node == null)
            return new HashSet<>();
        return new HashSet<>(successorMap.getOrDefault(node, new HashSet<>()));
    }

    /**
     * Find all METHOD_CALL nodes that invoke a specific target method
     * (app-agnostic)
     */
    public List<AllocationNode> findMethodCallNodes(SootMethod targetMethod) {
        if (targetMethod == null)
            return new ArrayList<>();

        Set<AllocationNode> callNodes = methodCallMap.get(targetMethod);
        return callNodes != null ? new ArrayList<>(callNodes) : new ArrayList<>();
    }

    /**
     * Find predecessor nodes that are conditions (IF_CONDITION or SWITCH) leading
     * to target
     */
    public List<AllocationNode> findPredecessorConditions(AllocationNode targetNode) {
        if (targetNode == null)
            return new ArrayList<>();

        List<AllocationNode> conditionPredecessors = new ArrayList<>();
        Set<AllocationNode> visited = new HashSet<>();

        findPredecessorConditionsRecursive(targetNode, conditionPredecessors, visited);

        return conditionPredecessors;
    }

    /**
     * Recursive helper to find predecessor conditions
     */
    private void findPredecessorConditionsRecursive(AllocationNode currentNode,
            List<AllocationNode> conditionPredecessors,
            Set<AllocationNode> visited) {
        if (currentNode == null || visited.contains(currentNode)) {
            return;
        }

        visited.add(currentNode);
        Set<AllocationNode> predecessors = getPredecessors(currentNode);

        for (AllocationNode pred : predecessors) {
            if (pred.getType() == NodeType.IF_CONDITION || pred.getType() == NodeType.SWITCH) {
                conditionPredecessors.add(pred);
                // Continue searching backward from this condition
                findPredecessorConditionsRecursive(pred, conditionPredecessors, visited);
            } else {
                // If predecessor is not a condition, continue searching
                findPredecessorConditionsRecursive(pred, conditionPredecessors, visited);
            }
        }
    }

    /**
     * Get all nodes of a specific type
     */
    public Set<AllocationNode> getNodesOfType(NodeType type) {
        return new HashSet<>(nodesByType.getOrDefault(type, new HashSet<>()));
    }

    /**
     * Find the complete backward path from a node to entry points
     */
    public List<List<AllocationNode>> getPathsToEntry(AllocationNode startNode) {
        if (startNode == null)
            return new ArrayList<>();

        List<List<AllocationNode>> allPaths = new ArrayList<>();
        List<AllocationNode> currentPath = new ArrayList<>();
        Set<AllocationNode> visited = new HashSet<>();

        findPathsToEntryRecursive(startNode, currentPath, allPaths, visited);

        return allPaths;
    }

    /**
     * Recursive helper to find all paths to entry
     */
    private void findPathsToEntryRecursive(AllocationNode currentNode,
            List<AllocationNode> currentPath,
            List<List<AllocationNode>> allPaths,
            Set<AllocationNode> visited) {
        if (currentNode == null || visited.contains(currentNode)) {
            return;
        }

        currentPath.add(0, currentNode); // Add to beginning (backward path)
        visited.add(currentNode);

        Set<AllocationNode> predecessors = getPredecessors(currentNode);

        if (predecessors.isEmpty() || entryNodes.contains(currentNode)) {
            // Reached entry point - save this path
            allPaths.add(new ArrayList<>(currentPath));
        } else {
            // Continue backward through each predecessor
            for (AllocationNode pred : predecessors) {
                findPathsToEntryRecursive(pred, new ArrayList<>(currentPath), allPaths, visited);
            }
        }

        visited.remove(currentNode);
    }

    /**
     * Find immediate predecessor condition of a target node
     */
    public AllocationNode findImmediatePredecessorCondition(AllocationNode targetNode) {
        if (targetNode == null)
            return null;

        Set<AllocationNode> predecessors = getPredecessors(targetNode);

        // First check direct predecessors
        for (AllocationNode pred : predecessors) {
            if (pred.getType() == NodeType.IF_CONDITION || pred.getType() == NodeType.SWITCH) {
                return pred;
            }
        }

        // If no direct condition predecessors, search one level deeper
        for (AllocationNode pred : predecessors) {
            AllocationNode condition = findImmediatePredecessorCondition(pred);
            if (condition != null) {
                return condition;
            }
        }

        return null;
    }

    /**
     * Get all nodes that can reach a target node (forward reachability)
     */
    public Set<AllocationNode> getNodesReaching(AllocationNode targetNode) {
        if (targetNode == null)
            return new HashSet<>();

        Set<AllocationNode> reachingNodes = new HashSet<>();
        Set<AllocationNode> visited = new HashSet<>();

        findNodesReachingRecursive(targetNode, reachingNodes, visited);

        return reachingNodes;
    }

    /**
     * Recursive helper for forward reachability
     */
    private void findNodesReachingRecursive(AllocationNode currentNode,
            Set<AllocationNode> reachingNodes,
            Set<AllocationNode> visited) {
        if (currentNode == null || visited.contains(currentNode)) {
            return;
        }

        visited.add(currentNode);
        reachingNodes.add(currentNode);

        Set<AllocationNode> predecessors = getPredecessors(currentNode);
        for (AllocationNode pred : predecessors) {
            findNodesReachingRecursive(pred, reachingNodes, visited);
        }
    }

    /**
     * Check if there's a path from source to target node
     */
    public boolean hasPath(AllocationNode source, AllocationNode target) {
        if (source == null || target == null)
            return false;
        if (source.equals(target))
            return true;

        Set<AllocationNode> visited = new HashSet<>();
        return hasPathRecursive(source, target, visited);
    }

    /**
     * Recursive helper for path checking
     */
    private boolean hasPathRecursive(AllocationNode current, AllocationNode target, Set<AllocationNode> visited) {
        if (current == null || visited.contains(current)) {
            return false;
        }

        if (current.equals(target)) {
            return true;
        }

        visited.add(current);

        Set<AllocationNode> successors = getSuccessors(current);
        for (AllocationNode successor : successors) {
            if (hasPathRecursive(successor, target, visited)) {
                return true;
            }
        }

        return false;
    }

    // ===== EXISTING FUNCTIONALITY (PRESERVED) =====

    /**
     * Extract SootMethod from method signature
     */
    private SootMethod extractMethodFromSignature(String signature) {
        try {
            // This is a simplified extraction - in practice you'd need more robust parsing
            for (SootClass sootClass : Scene.v().getApplicationClasses()) {
                for (SootMethod method : sootClass.getMethods()) {
                    if (method.getSignature().equals(signature)) {
                        return method;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error extracting method from signature: " + signature);
        }
        return null;
    }

    /**
     * Get all nodes in the graph
     */
    public Set<AllocationNode> getNodes() {
        return new HashSet<>(nodes);
    }

    /**
     * Get a node by its ID
     */
    public AllocationNode getNodeById(String id) {
        return nodeById.get(id);
    }

    /**
     * Get all allocation nodes (nodes that create objects)
     */
    public List<AllocationNode> getAllocationNodes() {
        return nodes.stream()
                .filter(AllocationNode::isAllocation)
                .collect(Collectors.toList());
    }

    /**
     * Get all method call nodes
     */
    public List<AllocationNode> getMethodCallNodes() {
        return new ArrayList<>(nodesByType.get(NodeType.METHOD_CALL));
    }

    /**
     * Get all condition nodes (IF and SWITCH)
     */
    public List<AllocationNode> getConditionNodes() {
        List<AllocationNode> conditions = new ArrayList<>();
        conditions.addAll(nodesByType.get(NodeType.IF_CONDITION));
        conditions.addAll(nodesByType.get(NodeType.SWITCH));
        return conditions;
    }

    /**
     * Get entry nodes
     */
    public Set<AllocationNode> getEntryNodes() {
        return new HashSet<>(entryNodes);
    }

    /**
     * Get the first entry node (for backward compatibility)
     */
    public AllocationNode getEntryNode() {
        return entryNodes.isEmpty() ? null : entryNodes.iterator().next();
    }

    /**
     * Get exit nodes
     */
    public Set<AllocationNode> getExitNodes() {
        return new HashSet<>(exitNodes);
    }

    /**
     * Get the method this graph represents
     */
    public SootMethod getMethod() {
        return method;
    }

    /**
     * Get the method signature
     */
    public String getMethodSignature() {
        return methodSignature;
    }

    /**
     * Get graph statistics
     */
    public Map<String, Integer> getStatistics() {
        Map<String, Integer> stats = new HashMap<>();

        stats.put("total_nodes", nodes.size());
        stats.put("allocation_nodes", nodesByType.get(NodeType.ALLOCATION).size());
        stats.put("method_call_nodes", nodesByType.get(NodeType.METHOD_CALL).size());
        stats.put("condition_nodes", nodesByType.get(NodeType.IF_CONDITION).size() +
                nodesByType.get(NodeType.SWITCH).size());
        stats.put("entry_nodes", entryNodes.size());
        stats.put("exit_nodes", exitNodes.size());

        return stats;
    }

    /**
     * Check if the graph is empty
     */
    public boolean isEmpty() {
        return nodes.isEmpty();
    }

    /**
     * Clear all data (for cleanup)
     */
    public void clear() {
        nodes.clear();
        nodesByType.clear();
        nodeById.clear();
        entryNodes.clear();
        exitNodes.clear();
        predecessorMap.clear();
        successorMap.clear();
        methodCallMap.clear();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AllocationGraph for ").append(methodSignature).append("\n");
        sb.append("Nodes: ").append(nodes.size()).append("\n");

        Map<String, Integer> stats = getStatistics();
        stats.forEach((key, value) -> sb.append("  ").append(key).append(": ").append(value).append("\n"));

        return sb.toString();
    }
}