package soot.jimple.infoflow.cmd;

import soot.Scene;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class CallGraphAnalyzer {
    private CallGraph callGraph;
    private String startMethodSignature;

    public CallGraphAnalyzer(String startMethodSig) {
        this.startMethodSignature = startMethodSig;
    }

    public void buildCallGraph() {
        // Just get the call graph from Soot
        callGraph = Scene.v().getCallGraph();
    }

    public List<List<SootMethod>> findPathsToLeaves() {
        List<List<SootMethod>> allPaths = new ArrayList<>();
        SootMethod startMethod = Scene.v().getMethod(startMethodSignature);

        if (startMethod != null) {
            Set<SootMethod> visited = new HashSet<>();
            List<SootMethod> currentPath = new ArrayList<>();
            findPaths(startMethod, visited, currentPath, allPaths);
        }

        return allPaths;
    }

    private void findPaths(SootMethod currentMethod,
            Set<SootMethod> visited,
            List<SootMethod> currentPath,
            List<List<SootMethod>> allPaths) {

        visited.add(currentMethod);
        currentPath.add(currentMethod);

        boolean isLeaf = true;
        Iterator<Edge> edges = callGraph.edgesOutOf(currentMethod);

        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod target = edge.tgt();

            // Simply check if method hasn't been visited
            if (!visited.contains(target)) {
                isLeaf = false;
                findPaths(target, visited, currentPath, allPaths);
            }
        }

        if (isLeaf && currentPath.size() > 1) {
            allPaths.add(new ArrayList<>(currentPath));
        }

        visited.remove(currentMethod);
        currentPath.remove(currentPath.size() - 1);
    }

    public void printPaths(List<List<SootMethod>> paths) {
        System.out.println("\n=== Call Paths From " + startMethodSignature + " ===\n");

        if (paths.isEmpty()) {
            System.out.println("No paths found.");
            return;
        }

        for (int i = 0; i < paths.size(); i++) {
            System.out.println("Path " + (i + 1) + ":");
            List<SootMethod> path = paths.get(i);
            int depth = 0;

            for (SootMethod method : path) {
                String indent = "  ".repeat(depth);
                System.out.println(indent + "-> " + method.getSignature());
                depth++;
            }
            System.out.println();
        }

        System.out.println("Total paths found: " + paths.size());
    }
}