package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;

/**
 * Builds composite paths using recursive scenario generation
 * Creates realistic execution scenarios for symbolic execution guidance
 */
public class CompositePathBuilder {

    private final MethodPathEnumerator pathEnumerator;
    private final CallSiteAnalyzer callSiteAnalyzer;
    private final Map<SootMethod, BlockCFGExtractor.MethodCFG> methodCFGs;
    private final String appPackageName;

    public CompositePathBuilder(String appPackageName, MethodPathEnumerator pathEnumerator,
            CallSiteAnalyzer callSiteAnalyzer,
            Map<SootMethod, BlockCFGExtractor.MethodCFG> methodCFGs) {
        this.appPackageName = appPackageName;
        this.pathEnumerator = pathEnumerator;
        this.callSiteAnalyzer = callSiteAnalyzer;
        this.methodCFGs = methodCFGs;
    }

    /**
     * Build all composite paths starting from entry points
     */
    public List<CompositePath> buildCompositePaths(Set<SootMethod> entryPoints) {
        System.out.println("\n=== Building Composite Paths (Recursive Generation) ===");

        List<CompositePath> allCompositePaths = new ArrayList<>();

        for (SootMethod entryPoint : entryPoints) {
            if (isAppMethod(entryPoint)) {
                System.out.println("\n--- Processing Entry Point: " + entryPoint.getName() + " ---");
                List<CompositePath> entryPaths = generateScenariosFromEntry(entryPoint);
                allCompositePaths.addAll(entryPaths);

                System.out.println("Entry point " + entryPoint.getName() + " generated " +
                        entryPaths.size() + " complete scenarios");
            }
        }

        System.out.println("\n=== Composite Path Generation Complete ===");
        System.out.println("Total composite paths: " + allCompositePaths.size());
        return allCompositePaths;
    }

    /**
     * Generate complete execution scenarios starting from a specific entry point
     */
    private List<CompositePath> generateScenariosFromEntry(SootMethod entryMethod) {
        List<CompositePath> allScenarios = new ArrayList<>();

        // Get all internal paths for the entry method
        BlockCFGExtractor.MethodCFG entryCFG = methodCFGs.get(entryMethod);
        if (entryCFG == null) {
            System.out.println("No CFG available for entry method: " + entryMethod.getName());
            return allScenarios;
        }

        List<MethodPathEnumerator.MethodPath> entryPaths = pathEnumerator.getMethodPaths(entryMethod, entryCFG);
        System.out.println("Entry method has " + entryPaths.size() + " internal paths");

        // Generate complete scenarios for each entry path
        for (MethodPathEnumerator.MethodPath entryPath : entryPaths) {
            System.out.println("\n📋 Processing entry path: " + entryPath.getPathSummary());

            // Create initial composite path with just the entry method
            CompositePath initialPath = CompositePath.createInitial(entryMethod, entryPath);

            // Recursively resolve all call sites to generate complete scenarios
            List<CompositePath> completeScenarios = resolveAllCallSites(initialPath, entryPath);
            allScenarios.addAll(completeScenarios);

            System.out.println("Generated " + completeScenarios.size() + " complete scenarios from this entry path");
        }

        return allScenarios;
    }

    /**
     * Recursively resolve all call sites in a method path to generate complete
     * scenarios
     */
    private List<CompositePath> resolveAllCallSites(CompositePath currentPath,
            MethodPathEnumerator.MethodPath methodPath) {
        List<CompositePath> completeScenarios = new ArrayList<>();

        // Find all call sites in this method path
        List<CallSiteAnalyzer.CallSite> callSites = findCallSitesInMethodPath(methodPath);

        if (callSites.isEmpty()) {
            // No call sites - this is a complete scenario
            System.out.println("  ✅ Complete scenario: " + currentPath.getPathSummary());
            completeScenarios.add(currentPath);
            return completeScenarios;
        }

        // Process first call site
        CallSiteAnalyzer.CallSite firstCallSite = callSites.get(0);
        System.out.println("  🔍 Resolving call site: " + firstCallSite.callerMethod.getName() +
                " → " + firstCallSite.targetMethod.getName());

        // Check if we should expand this call
        if (!isAppMethod(firstCallSite.targetMethod)) {
            System.out.println("    🚫 Skipping non-app method: " + firstCallSite.targetMethod.getName());
            // Treat as complete scenario (don't expand framework calls)
            completeScenarios.add(currentPath);
            return completeScenarios;
        }

        // Get all possible paths through the target method
        BlockCFGExtractor.MethodCFG targetCFG = methodCFGs.get(firstCallSite.targetMethod);
        if (targetCFG == null) {
            System.out.println("    ❌ No CFG for target method: " + firstCallSite.targetMethod.getName());
            // Treat as complete scenario
            completeScenarios.add(currentPath);
            return completeScenarios;
        }

        List<MethodPathEnumerator.MethodPath> targetPaths = pathEnumerator.getMethodPaths(firstCallSite.targetMethod,
                targetCFG);
        System.out.println("    📝 Target method has " + targetPaths.size() + " internal paths");

        // Generate scenarios for each target path
        for (MethodPathEnumerator.MethodPath targetPath : targetPaths) {
            System.out.println("      🎯 Combining with target path: " + targetPath.getPathSummary());

            // Create new composite path by combining current path with target method
            CompositePath combinedPath = CompositePath.combine(currentPath, firstCallSite, targetPath);

            // Recursively resolve any call sites in the target method
            List<CompositePath> targetScenarios = resolveAllCallSites(combinedPath, targetPath);
            completeScenarios.addAll(targetScenarios);
        }

        return completeScenarios;
    }

    /**
     * Find all call sites within a specific method path
     */
    private List<CallSiteAnalyzer.CallSite> findCallSitesInMethodPath(MethodPathEnumerator.MethodPath methodPath) {
        List<CallSiteAnalyzer.CallSite> pathCallSites = new ArrayList<>();

        // Check each block in the method path for call sites
        for (String blockId : methodPath.blockSequence) {
            List<CallSiteAnalyzer.CallSite> blockCallSites = callSiteAnalyzer.getCallSitesForBlock(blockId);
            pathCallSites.addAll(blockCallSites);
        }

        return pathCallSites;
    }

    /**
     * Check if method belongs to app package and should be expanded
     */
    private boolean isAppMethod(SootMethod method) {
        String packageName = method.getDeclaringClass().getPackageName();
        String methodName = method.getName();

        // Must be in app package
        if (!packageName.startsWith(appPackageName)) {
            return false;
        }

        // Skip parse methods (utility methods that cause explosion)
       // if (methodName.toLowerCase().contains("parse")) {
         //   System.out.println("    🚫 Skipping parse method: " + methodName);
           // return false;
        //}

        return true;
    }

    /**
     * Represents a complete execution scenario through the application
     */
    public static class CompositePath {
        private final SootMethod entryPoint;
        private final List<MethodExecution> methodExecutions;
        private int pathId;

        // Private constructor - use factory methods
        private CompositePath(SootMethod entryPoint, List<MethodExecution> executions) {
            this.entryPoint = entryPoint;
            this.methodExecutions = Collections.unmodifiableList(new ArrayList<>(executions));
            this.pathId = -1;
        }

        /**
         * Create initial composite path with just entry method
         */
        public static CompositePath createInitial(SootMethod entryPoint, MethodPathEnumerator.MethodPath entryPath) {
            List<MethodExecution> executions = new ArrayList<>();
            executions.add(new MethodExecution(entryPath, null, null));
            return new CompositePath(entryPoint, executions);
        }

        /**
         * Create composite path by combining caller path with callee method
         */
        public static CompositePath combine(CompositePath callerPath, CallSiteAnalyzer.CallSite callSite,
                MethodPathEnumerator.MethodPath calleePath) {
            List<MethodExecution> newExecutions = new ArrayList<>(callerPath.methodExecutions);

            // Find the caller execution that contains this call site
            MethodExecution callerExecution = null;
            for (MethodExecution execution : callerPath.methodExecutions) {
                if (execution.methodPath.method.equals(callSite.callerMethod)) {
                    callerExecution = execution;
                    break;
                }
            }

            // Add callee execution
            MethodExecution calleeExecution = new MethodExecution(calleePath, callerExecution, callSite);
            newExecutions.add(calleeExecution);

            return new CompositePath(callerPath.entryPoint, newExecutions);
        }

        public List<MethodExecution> getMethodExecutions() {
            return methodExecutions; // Already unmodifiable
        }

        public SootMethod getEntryPoint() {
            return entryPoint;
        }

        public void setPathId(int pathId) {
            this.pathId = pathId;
        }

        public int getPathId() {
            return pathId;
        }

        /**
         * Get call depth of this composite path
         */
        public int getCallDepth() {
            return methodExecutions.size();
        }

        /**
         * Get total number of blocks in this composite path
         */
        public int getTotalBlocks() {
            return methodExecutions.stream()
                    .mapToInt(exec -> exec.methodPath.getLength())
                    .sum();
        }

        /**
         * Get readable summary of this path
         */
        public String getPathSummary() {
            StringBuilder summary = new StringBuilder();
            summary.append("Entry: ").append(entryPoint.getName());

            for (MethodExecution execution : methodExecutions) {
                if (execution.callerExecution != null) {
                    summary.append(" -> ").append(execution.methodPath.method.getName());
                }
            }

            summary.append(" (").append(getTotalBlocks()).append(" blocks)");
            return summary.toString();
        }

        @Override
        public String toString() {
            return "CompositePath[" + pathId + "]: " + getPathSummary();
        }

        /**
         * Represents execution of one method within the composite path
         */
        public static class MethodExecution {
            public final MethodPathEnumerator.MethodPath methodPath;
            public final MethodExecution callerExecution;
            public final CallSiteAnalyzer.CallSite callSite;

            public MethodExecution(MethodPathEnumerator.MethodPath methodPath,
                    MethodExecution callerExecution,
                    CallSiteAnalyzer.CallSite callSite) {
                this.methodPath = methodPath;
                this.callerExecution = callerExecution;
                this.callSite = callSite;
            }

            @Override
            public String toString() {
                return methodPath.method.getName() + " path: " + methodPath.getPathSummary();
            }
        }
    }
}