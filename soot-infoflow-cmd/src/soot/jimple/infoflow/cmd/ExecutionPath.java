package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

/**
 * Represents a single execution path from a root method to the sink.
 * Path is built backward (from sink toward root), then reversed for storage.
 */
public class ExecutionPath {

    private String pathId;
    private List<SootMethod> methods; // Ordered from root -> sink
    private List<Edge> edges; // Call edges between methods
    private boolean containsCycle;

    public ExecutionPath(String pathId) {
        this.pathId = pathId;
        this.methods = new ArrayList<>();
        this.edges = new ArrayList<>();
        this.containsCycle = false;
    }

    /**
     * Add a method to the path.
     * Checks if method already exists (cycle detection).
     */
    public void addMethod(SootMethod method) {
        if (methods.contains(method)) {
            containsCycle = true;
        }
        methods.add(method);
    }

    /**
     * Add a call edge to the path
     */
    public void addEdge(Edge edge) {
        edges.add(edge);
    }

    /**
     * Get the path length (number of methods)
     */
    public int getLength() {
        return methods.size();
    }

    /**
     * Check if this path contains a cycle
     */
    public boolean containsCycle() {
        return containsCycle;
    }

    /**
     * Get all methods in the path (unmodifiable)
     */
    public List<SootMethod> getMethods() {
        return Collections.unmodifiableList(methods);
    }

    /**
     * Get all edges in the path (unmodifiable)
     */
    public List<Edge> getEdges() {
        return Collections.unmodifiableList(edges);
    }

    /**
     * Get the last method in the path (the sink)
     */
    public SootMethod getLastMethod() {
        return methods.isEmpty() ? null : methods.get(methods.size() - 1);
    }

    /**
     * Get the first method in the path (the root)
     */
    public SootMethod getFirstMethod() {
        return methods.isEmpty() ? null : methods.get(0);
    }

    /**
     * Get path ID
     */
    public String getPathId() {
        return pathId;
    }

    /**
     * Create a copy of this path (for branching during traversal)
     */
    public ExecutionPath copy(String newPathId) {
        ExecutionPath newPath = new ExecutionPath(newPathId);
        newPath.methods = new ArrayList<>(this.methods);
        newPath.edges = new ArrayList<>(this.edges);
        newPath.containsCycle = this.containsCycle;
        return newPath;
    }

    /**
     * Reverse the path order.
     * Used after backward traversal to get root->sink order.
     */
    public void reverse() {
        Collections.reverse(methods);
        Collections.reverse(edges);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Path ").append(pathId).append(":\n");
        sb.append("  Length: ").append(getLength()).append(" methods\n");
        sb.append("  Methods:\n");
        for (int i = 0; i < methods.size(); i++) {
            sb.append("    ").append(i + 1).append(". ")
                    .append(methods.get(i).getSignature()).append("\n");
        }
        if (containsCycle) {
            sb.append("  [WARNING: Contains cycle]\n");
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof ExecutionPath))
            return false;
        ExecutionPath other = (ExecutionPath) obj;
        return this.methods.equals(other.methods);
    }

    @Override
    public int hashCode() {
        return methods.hashCode();
    }
}