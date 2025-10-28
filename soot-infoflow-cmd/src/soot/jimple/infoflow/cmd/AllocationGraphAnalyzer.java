package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

public class AllocationGraphAnalyzer {
    private final Map<SootMethod, AllocationGraph> methodGraphs;
    private final Set<SootMethod> analyzedMethods;
    private final Map<SootClass, Set<SootMethod>> componentToMethods;
    private final Map<String, Set<SootClass>> componentTypeToClasses;
    private final Set<SootMethod> processingMethods;
    private SootMethod dummyMainMethod;
    private CallGraph callGraph;

    public AllocationGraphAnalyzer() {
        this.methodGraphs = new HashMap<>();
        this.analyzedMethods = new HashSet<>();
        this.componentToMethods = new HashMap<>();
        this.componentTypeToClasses = new HashMap<>();
        this.processingMethods = new HashSet<>();
        initializeComponentMaps();
    }

    private void initializeComponentMaps() {
        componentTypeToClasses.put("activity", new HashSet<>());
        componentTypeToClasses.put("service", new HashSet<>());
        componentTypeToClasses.put("receiver", new HashSet<>());
        componentTypeToClasses.put("provider", new HashSet<>());
    }

    public void initializeAnalysis() {
        try {
            // Get the call graph
            this.callGraph = Scene.v().getCallGraph();
            this.dummyMainMethod = findDummyMainMethod(callGraph);
            if (dummyMainMethod == null) {
                throw new RuntimeException("Could not find FlowDroid's dummy main method");
            }

            // Process dummy methods to find components
            processComponentDummyMethods();

        } catch (RuntimeException e) {
            System.err.println("Error initializing analysis: " + e.getMessage());
            throw e;
        }
    }

    private SootMethod findDummyMainMethod(CallGraph callGraph) {
        for (Edge edge : callGraph) {
            SootMethod src = edge.src();
            if (src.getName().equals("dummyMainMethod") &&
                    src.getDeclaringClass().getName().equals("dummyMainClass")) {
                return src;
            }
        }
        return null;
    }

    private void processComponentDummyMethods() {
        Queue<Edge> toProcess = new LinkedList<>();
        Set<SootMethod> processed = new HashSet<>();

        // Start with edges from dummy main
        callGraph.edgesOutOf(dummyMainMethod).forEachRemaining(toProcess::add);

        while (!toProcess.isEmpty()) {
            Edge edge = toProcess.poll();
            SootMethod target = edge.tgt();

            if (processed.contains(target))
                continue;
            processed.add(target);

            if (target.getName().contains("dummyMainMethod_")) {
                String componentName = target.getName().substring(target.getName().indexOf('_') + 1).replace('_', '.');
                try {
                    SootClass componentClass = Scene.v().getSootClass(componentName);
                    String componentType = determineComponentType(componentClass);
                    if (componentType != null) {
                        componentTypeToClasses.get(componentType).add(componentClass);

                        // Process component's methods from call graph
                        Iterator<Edge> componentEdges = callGraph.edgesOutOf(target);
                        while (componentEdges.hasNext()) {
                            Edge compEdge = componentEdges.next();
                            SootMethod compMethod = compEdge.tgt();
                            if (compMethod.getDeclaringClass().equals(componentClass)) {
                                componentToMethods.computeIfAbsent(componentClass, k -> new HashSet<>())
                                        .add(compMethod);
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    System.err.println("Error processing component " + componentName + ": " + e.getMessage());
                }
            }
        }
    }

    public void analyze() {
        if (dummyMainMethod == null) {
            throw new RuntimeException("Analysis not initialized. Call initializeAnalysis first.");
        }

        try {
            // Process components
            for (Set<SootClass> components : componentTypeToClasses.values()) {
                for (SootClass component : components) {
                    for (SootMethod method : componentToMethods.getOrDefault(component, new HashSet<>())) {
                        if (!analyzedMethods.contains(method)) {
                            analyzeMethod(method);
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error during analysis: " + e.getMessage());
            throw e;
        }
    }

    private void analyzeMethod(SootMethod method) {
        if (analyzedMethods.contains(method) ||
                method.getName().equals("<init>") ||
                method.getName().contains("dummyMainMethod")) {
            return;
        }

        analyzedMethods.add(method);

        // Get or create method's allocation graph
        AllocationGraph graph = getOrCreateMethodGraph(method);
        if (graph == null)
            return;

        // Process callees from call graph
        Iterator<Edge> edges = callGraph.edgesOutOf(method);
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod callee = edge.tgt();
            if (!analyzedMethods.contains(callee)) {
                analyzeMethod(callee);
            }
        }
    }

    public AllocationGraph getOrCreateMethodGraph(SootMethod method) {
        // Return existing graph if available
        AllocationGraph existingGraph = methodGraphs.get(method);
        if (existingGraph != null) {
            return existingGraph;
        }

        // Don't create graphs for dummy methods
        if (method.getName().contains("dummyMainMethod")) {
            return null;
        }

        // Avoid cycles and constructors
        if (processingMethods.contains(method) || method.getName().equals("<init>")) {
            return null;
        }

        // Create new graph for method with body
        if (method.hasActiveBody()) {
            processingMethods.add(method);
            AllocationGraph newGraph = new AllocationGraph(method.getSignature(), this);
            methodGraphs.put(method, newGraph);
            processingMethods.remove(method);
            return newGraph;
        }

        return null;
    }

    private String determineComponentType(SootClass cls) {
        while (cls.hasSuperclass()) {
            String name = cls.getName();
            if (name.contains("Activity") || cls.getSuperclass().getName().contains("Activity")) {
                return "activity";
            } else if (name.contains("Service") || cls.getSuperclass().getName().contains("Service")) {
                return "service";
            } else if (name.contains("Receiver") || cls.getSuperclass().getName().contains("BroadcastReceiver")) {
                return "receiver";
            } else if (name.contains("Provider") || cls.getSuperclass().getName().contains("ContentProvider")) {
                return "provider";
            }
            cls = cls.getSuperclass();
        }
        return null;
    }

    public SootMethod findOnCreateMethod(SootClass activityClass) {
        try {
            return activityClass.getMethod("void onCreate(android.os.Bundle)");
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static class MethodAnalysisResult {
        private final SootMethod method;
        private final List<List<AllocationNode>> allocationPaths;
        private final Set<SootMethod> callees;
        private final PathContext context;

        public MethodAnalysisResult(SootMethod method,
                List<List<AllocationNode>> allocationPaths,
                Set<SootMethod> callees) {
            this.method = method;
            this.allocationPaths = allocationPaths;
            this.callees = callees;
            this.context = new PathContext();
        }

        public List<List<AllocationNode>> getAllocationPaths() {
            return allocationPaths;
        }

        public Set<SootMethod> getCallees() {
            return callees;
        }

        public PathContext getContext() {
            return context;
        }
    }

    public static class PathContext {
        private final List<SootMethod> methodPath;
        private boolean isHandler;

        public PathContext() {
            this.methodPath = new ArrayList<>();
            this.isHandler = false;
        }

        public void markAsHandler() {
            this.isHandler = true;
        }

        public boolean isHandler() {
            return isHandler;
        }

        public SootMethod getParentMethod() {
            return methodPath.size() < 2 ? null : methodPath.get(methodPath.size() - 2);
        }
    }

    // Getters
    public Map<SootMethod, AllocationGraph> getMethodGraphs() {
        return Collections.unmodifiableMap(methodGraphs);
    }

    public Set<SootMethod> getAnalyzedMethods() {
        return Collections.unmodifiableSet(analyzedMethods);
    }

    public Map<SootClass, Set<SootMethod>> getComponentToMethods() {
        return Collections.unmodifiableMap(componentToMethods);
    }

    public Map<String, Set<SootClass>> getComponentTypeToClasses() {
        return Collections.unmodifiableMap(componentTypeToClasses);
    }

    public CallGraph getCallGraph() {
        return callGraph;
    }

    public SootMethod getDummyMainMethod() {
        return dummyMainMethod;
    }
}