package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

/**
 * Stores the results of backward reachability analysis.
 * Contains all methods that can reach the sink and all complete paths.
 */
public class ReachabilityGraph {

    private SootMethod sink;
    private Set<SootMethod> reachableMethods;
    private Map<SootMethod, Set<SootMethod>> callersMap; // method -> set of its callers
    private Map<SootMethod, Set<Edge>> incomingEdges; // method -> edges into it
    private List<ExecutionPath> completePaths; // all complete paths found

    public ReachabilityGraph(SootMethod sink) {
        this.sink = sink;
        this.reachableMethods = new HashSet<>();
        this.callersMap = new HashMap<>();
        this.incomingEdges = new HashMap<>();
        this.completePaths = new ArrayList<>();

        // Sink is always reachable from itself
        reachableMethods.add(sink);
        callersMap.put(sink, new HashSet<>());
        incomingEdges.put(sink, new HashSet<>());
    }

    /**
     * Add a method as reachable
     */
    public void addReachableMethod(SootMethod method) {
        reachableMethods.add(method);
        callersMap.putIfAbsent(method, new HashSet<>());
        incomingEdges.putIfAbsent(method, new HashSet<>());
    }

    /**
     * Record that 'caller' calls 'callee'
     * This establishes the backward reachability relationship
     */
    public void addCaller(SootMethod callee, SootMethod caller, Edge edge) {
        // Ensure both methods are in the graph
        addReachableMethod(callee);
        addReachableMethod(caller);

        // Record the caller relationship
        callersMap.get(callee).add(caller);
        incomingEdges.get(callee).add(edge);
    }

    /**
     * Add a complete path (from root to sink)
     */
    public void addCompletePath(ExecutionPath path) {
        completePaths.add(path);
    }

    /**
     * Get all methods that can reach the sink
     */
    public Set<SootMethod> getReachableMethods() {
        return Collections.unmodifiableSet(reachableMethods);
    }

    /**
     * Get all callers of a specific method
     */
    public Set<SootMethod> getCallers(SootMethod method) {
        return callersMap.getOrDefault(method, Collections.emptySet());
    }

    /**
     * Get all incoming edges to a method
     */
    public Set<Edge> getIncomingEdges(SootMethod method) {
        return incomingEdges.getOrDefault(method, Collections.emptySet());
    }

    /**
     * Get all complete paths found
     */
    public List<ExecutionPath> getCompletePaths() {
        return Collections.unmodifiableList(completePaths);
    }

    /**
     * Get the sink method
     */
    public SootMethod getSink() {
        return sink;
    }

    /**
     * Check if a method can reach the sink
     */
    public boolean isReachable(SootMethod method) {
        return reachableMethods.contains(method);
    }

    /**
     * Get methods with no callers (root methods)
     */
    public Set<SootMethod> getRootMethods() {
        Set<SootMethod> roots = new HashSet<>();
        for (SootMethod method : reachableMethods) {
            if (getCallers(method).isEmpty() && !method.equals(sink)) {
                roots.add(method);
            }
        }
        return roots;
    }

    /**
     * Get statistics summary
     */
    public String getStatistics() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Reachability Graph Statistics ===\n");
        sb.append("Sink: ").append(sink.getSignature()).append("\n");
        sb.append("Total reachable methods: ").append(reachableMethods.size()).append("\n");
        sb.append("Root methods (no callers): ").append(getRootMethods().size()).append("\n");
        sb.append("Complete paths found: ").append(completePaths.size()).append("\n");

        if (!completePaths.isEmpty()) {
            int minLength = completePaths.stream()
                    .mapToInt(ExecutionPath::getLength)
                    .min().orElse(0);
            int maxLength = completePaths.stream()
                    .mapToInt(ExecutionPath::getLength)
                    .max().orElse(0);
            double avgLength = completePaths.stream()
                    .mapToInt(ExecutionPath::getLength)
                    .average().orElse(0.0);

            sb.append("Path lengths - min: ").append(minLength)
                    .append(", max: ").append(maxLength)
                    .append(", avg: ").append(String.format("%.2f", avgLength))
                    .append("\n");

            long cyclic = completePaths.stream()
                    .filter(ExecutionPath::containsCycle)
                    .count();
            if (cyclic > 0) {
                sb.append("Paths with cycles: ").append(cyclic).append("\n");
            }
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return "ReachabilityGraph{" +
                "sink=" + sink.getName() +
                ", reachableMethods=" + reachableMethods.size() +
                ", completePaths=" + completePaths.size() +
                '}';
    }
}