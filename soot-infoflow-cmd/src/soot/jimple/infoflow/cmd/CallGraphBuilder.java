package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

public class CallGraphBuilder {
    private final CallGraph originalCallGraph;
    private final Map<SootMethod, Set<SootMethod>> enhancedGraph;
    private final Map<SootMethod, Set<SootMethod>> virtualEdges;
    private final Set<SootMethod> processedMethods;

    public CallGraphBuilder() {
        this.originalCallGraph = Scene.v().getCallGraph();
        this.enhancedGraph = new HashMap<>();
        this.virtualEdges = new HashMap<>();
        this.processedMethods = new HashSet<>();
    }

    public void buildEnhancedGraph() {
        copyOriginalGraph();
        processOnClickListeners();
        handleSyntheticMethods();
    }

    private void copyOriginalGraph() {
        Iterator<Edge> edges = originalCallGraph.iterator();
        while (edges.hasNext()) {
            Edge edge = edges.next();
            addToEnhancedGraph(edge.src(), edge.tgt());
        }
    }

    private void addToEnhancedGraph(SootMethod source, SootMethod target) {
        enhancedGraph.computeIfAbsent(source, k -> new HashSet<>()).add(target);
    }

    private void processOnClickListeners() {
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.hasActiveBody()) {
                    findAndProcessOnClickListeners(method);
                }
            }
        }
    }

    private void findAndProcessOnClickListeners(SootMethod method) {
        if (!method.hasActiveBody() || processedMethods.contains(method)) {
            return;
        }
        processedMethods.add(method);

        Body body = method.getActiveBody();
        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof Stmt))
                continue;
            Stmt stmt = (Stmt) unit;

            if (stmt.containsInvokeExpr()) {
                InvokeExpr invoke = stmt.getInvokeExpr();
                if (isSetOnClickListener(invoke)) {
                    processOnClickListener(method, stmt, invoke);
                }
            }
        }
    }

    private boolean isSetOnClickListener(InvokeExpr invoke) {
        return invoke.getMethod().getName().equals("setOnClickListener") &&
                invoke.getMethod().getParameterCount() == 1 &&
                invoke.getMethod().getParameterType(0).toString().contains("OnClickListener");
    }

    private void processOnClickListener(SootMethod method, Stmt stmt, InvokeExpr invoke) {
        Value listener = invoke.getArg(0);

        if (listener instanceof NewExpr) {
            // Anonymous class or Lambda
            SootClass listenerClass = ((NewExpr) listener).getBaseType().getSootClass();
            if (isAnonymousClass(listenerClass)) {
                handleAnonymousClass(method, listenerClass);
            } else if (isSyntheticLambda(listenerClass)) {
                handleLambda(method, listenerClass);
            }
        } else if (listener instanceof Local) {
            // Method reference or implementing class
            handleMethodReference(method, (Local) listener);
        }
    }

    private boolean isAnonymousClass(SootClass cls) {
        return cls.getName().contains("$") &&
                Character.isDigit(cls.getName().charAt(cls.getName().lastIndexOf('$') + 1));
    }

    private boolean isSyntheticLambda(SootClass cls) {
        return cls.getName().contains("$$Lambda$") ||
                cls.getName().contains("$$ExternalSyntheticLambda");
    }

    private void handleAnonymousClass(SootMethod method, SootClass listenerClass) {
        for (SootMethod m : listenerClass.getMethods()) {
            if (m.getName().equals("onClick")) {
                addVirtualEdge(method, m);
            }
        }
    }

    private void handleLambda(SootMethod method, SootClass lambdaClass) {
        for (SootMethod m : lambdaClass.getMethods()) {
            if (m.getName().contains("$Lambda") || m.getName().contains("lambda$")) {
                addVirtualEdge(method, m);
            }
        }
    }

    private void handleMethodReference(SootMethod method, Local listener) {
        Type listenerType = listener.getType();
        if (listenerType instanceof RefType) {
            SootClass listenerClass = ((RefType) listenerType).getSootClass();
            for (SootMethod m : listenerClass.getMethods()) {
                if (m.getName().equals("onClick")) {
                    addVirtualEdge(method, m);
                }
            }
        }
    }

    private void handleSyntheticMethods() {
        Set<SootMethod> methods = new HashSet<>(enhancedGraph.keySet());
        for (SootMethod method : methods) {
            if (method.getName().contains("$$Nest$")) {
                processSyntheticMethod(method);
            }
        }
    }

    private void processSyntheticMethod(SootMethod syntheticMethod) {
        String name = syntheticMethod.getName();
        if (name.startsWith("$$Nest$m")) {
            String actualMethodName = name.substring("$$Nest$m".length());
            SootClass declaringClass = syntheticMethod.getDeclaringClass();

            for (SootMethod targetMethod : declaringClass.getMethods()) {
                if (targetMethod.getName().equals(actualMethodName)) {
                    addVirtualEdge(syntheticMethod, targetMethod);
                    // Also copy the target's callees
                    if (enhancedGraph.containsKey(targetMethod)) {
                        enhancedGraph.get(syntheticMethod).addAll(enhancedGraph.get(targetMethod));
                    }
                    break;
                }
            }
        }
    }

    private void addVirtualEdge(SootMethod source, SootMethod target) {
        virtualEdges.computeIfAbsent(source, k -> new HashSet<>()).add(target);
        addToEnhancedGraph(source, target);
    }

    public Set<SootMethod> getCallees(SootMethod method) {
        return enhancedGraph.getOrDefault(method, new HashSet<>());
    }

    public Set<SootMethod> getVirtualCallees(SootMethod method) {
        return virtualEdges.getOrDefault(method, new HashSet<>());
    }

    public Map<SootMethod, Set<SootMethod>> getEnhancedGraph() {
        return Collections.unmodifiableMap(enhancedGraph);
    }

    public Map<SootMethod, Set<SootMethod>> getVirtualEdges() {
        return Collections.unmodifiableMap(virtualEdges);
    }
}
