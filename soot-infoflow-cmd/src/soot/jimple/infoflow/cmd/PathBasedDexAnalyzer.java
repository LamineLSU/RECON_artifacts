package soot.jimple.infoflow.cmd;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import soot.Body;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.SwitchStmt;
import soot.jimple.ThrowStmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;

/**
 * PathBasedDexAnalyzer is a tool for analyzing DEX files to identify all
 * execution
 * paths through each method and the allocations/method calls that occur on
 * those paths.
 */
public class PathBasedDexAnalyzer {
    // Configuration
    private String dexFolderPath;
    private String outputPath;
    private int maxPathsPerMethod = 100; // Limit to avoid explosion
    private int maxLoopIterations = 2; // Limit loop iterations

    // Analysis state
    private Set<SootMethod> processedMethods;
    private Map<String, Object> originalSootState;

    // Classes for representing analysis results
    public static class DexFileAnalysis {
        public String dexFileName;
        public Map<String, ClassAnalysis> classes = new LinkedHashMap<>();
    }

    public static class ClassAnalysis {
        public Map<String, MethodAnalysis> methods = new LinkedHashMap<>();
    }

    public static class MethodAnalysis {
        public int totalPaths;
        public List<PathInfo> paths = new ArrayList<>();
    }

    public static class PathInfo {
        public int pathId;
        public List<Event> events = new ArrayList<>();
    }

    public static abstract class Event {
        public String type;
    }

    public static class AllocationEvent extends Event {
        public String objectType;

        public AllocationEvent(String type) {
            this.type = "allocation";
            this.objectType = type;
        }
    }

    public static class MethodCallEvent extends Event {
        public String signature;

        public MethodCallEvent(String methodSignature) {
            this.type = "methodCall";
            this.signature = methodSignature;
        }
    }

    /**
     * Helper class to track paths during DFS traversal
     */
    private static class PathState {
        Unit currentUnit;
        List<Unit> visitedUnits;
        List<Event> events;
        Map<Unit, Integer> visitCounts; // Track how many times each unit is visited

        public PathState(Unit start) {
            this.currentUnit = start;
            this.visitedUnits = new ArrayList<>();
            this.events = new ArrayList<>();
            this.visitCounts = new HashMap<>();
        }

        public PathState(PathState other) {
            this.currentUnit = other.currentUnit;
            this.visitedUnits = new ArrayList<>(other.visitedUnits);
            this.events = new ArrayList<>(other.events);
            this.visitCounts = new HashMap<>(other.visitCounts);
        }

        public void addEvent(Event event) {
            events.add(event);
        }

        public void visit(Unit unit) {
            visitedUnits.add(unit);
            currentUnit = unit;

            // Increment visit count for this unit
            visitCounts.put(unit, visitCounts.getOrDefault(unit, 0) + 1);
        }

        public boolean hasVisited(Unit unit) {
            return visitCounts.containsKey(unit);
        }

        public int getVisitCount(Unit unit) {
            return visitCounts.getOrDefault(unit, 0);
        }
    }

    public PathBasedDexAnalyzer(String dexFolderPath, String outputPath) {
        this.dexFolderPath = dexFolderPath;
        this.outputPath = outputPath;
        this.processedMethods = new HashSet<>();
        this.originalSootState = new HashMap<>();
    }

    public void setMaxPathsPerMethod(int maxPaths) {
        this.maxPathsPerMethod = maxPaths;
    }

    public void setMaxLoopIterations(int maxLoopIterations) {
        this.maxLoopIterations = maxLoopIterations;
    }

    /**
     * Main analysis method - processes all DEX files in the specified folder
     */
    public void analyzeDexFiles() {
        File folder = new File(dexFolderPath);
        File[] dexFiles = folder.listFiles((dir, name) -> name.endsWith(".dex"));

        if (dexFiles == null || dexFiles.length == 0) {
            System.out.println("No DEX files found in the specified folder: " + dexFolderPath);
            return;
        }

        System.out.println("Found " + dexFiles.length + " DEX files in " + dexFolderPath);

        // Save current Soot state before analysis
        saveCurrentSootState();

        try {
            for (File dexFile : dexFiles) {
                System.out.println("Analyzing: " + dexFile.getName());
                analyzeSingleDexFile(dexFile);
            }
        } finally {
            // Restore original Soot state after analysis
            restoreSootState();
        }
    }

    private void saveCurrentSootState() {
        // Save important Soot settings that we'll need to restore
        originalSootState.put("processDir", soot.options.Options.v().process_dir());
        originalSootState.put("androidJars", soot.options.Options.v().android_jars());
        originalSootState.put("srcPrec", soot.options.Options.v().src_prec());
        originalSootState.put("allowPhantomRefs", soot.options.Options.v().allow_phantom_refs());
        originalSootState.put("wholeProgram", soot.options.Options.v().whole_program());
    }

    private void restoreSootState() {
        // Restore the key settings we changed
        soot.options.Options.v().set_process_dir((List<String>) originalSootState.get("processDir"));
        soot.options.Options.v().set_android_jars((String) originalSootState.get("androidJars"));
        soot.options.Options.v().set_src_prec((Integer) originalSootState.get("srcPrec"));
        soot.options.Options.v().set_allow_phantom_refs((Boolean) originalSootState.get("allowPhantomRefs"));
        soot.options.Options.v().set_whole_program((Boolean) originalSootState.get("wholeProgram"));
    }

    /**
     * Analyzes a single DEX file
     */
    private void analyzeSingleDexFile(File dexFile) {
        try {
            // Reset state for this DEX file
            processedMethods.clear();

            // Configure Soot for this DEX file
            configureSootForDex(dexFile);

            // Create the result container
            DexFileAnalysis dexAnalysis = new DexFileAnalysis();
            dexAnalysis.dexFileName = dexFile.getName();

            // Get all classes in the DEX file
            List<SootClass> classList = new ArrayList<>();
            for (SootClass sc : Scene.v().getClasses()) {
                if (!sc.isPhantom() && !sc.isPhantomClass()) {
                    classList.add(sc);
                }
            }

            // Sort classes by name for consistent output
            classList.sort(Comparator.comparing(SootClass::getName));

            // Process each class
            for (SootClass sc : classList) {
                ClassAnalysis classAnalysis = new ClassAnalysis();

                // Process each method in the class
                List<SootMethod> methods = new ArrayList<>(sc.getMethods());
                methods.sort(Comparator.comparing(SootMethod::getSignature));

                for (SootMethod method : methods) {
                    if (method.hasActiveBody()) {
                        System.out.println("  Analyzing method: " + method.getSignature());
                        MethodAnalysis methodAnalysis = analyzeMethodPaths(method);
                        if (methodAnalysis != null && !methodAnalysis.paths.isEmpty()) {
                            classAnalysis.methods.put(method.getSignature(), methodAnalysis);
                        }
                    }
                }

                // Add class to analysis results if it has methods with paths
                if (!classAnalysis.methods.isEmpty()) {
                    dexAnalysis.classes.put(sc.getName(), classAnalysis);
                }
            }

            // Write the analysis results to a JSON file
            writeAnalysisToJson(dexAnalysis, dexFile.getName());

        } catch (Exception e) {
            System.err.println("Error analyzing " + dexFile.getName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void configureSootForDex(File dexFile) {
        // Configure Soot for analyzing this DEX file
        G.reset();
        soot.options.Options.v().set_process_dir(Collections.singletonList(dexFile.getAbsolutePath()));

        // Set the absolute path to your Android platforms directory
        String androidPlatformsPath = "C:\\Users\\Babangida Bappah\\Desktop\\Research\\flowdroid2\\android-platforms";
        soot.options.Options.v().set_android_jars(androidPlatformsPath);

        soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_apk);
        soot.options.Options.v().set_output_format(soot.options.Options.output_format_none);
        soot.options.Options.v().set_allow_phantom_refs(true);
        soot.options.Options.v().set_ignore_resolution_errors(true);
        soot.options.Options.v().set_whole_program(true);

        // Load classes
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();
    }

    /**
     * Analyzes a method to find all execution paths and their events
     */
    private MethodAnalysis analyzeMethodPaths(SootMethod method) {
        if (processedMethods.contains(method)) {
            return null; // Avoid recursion
        }

        processedMethods.add(method);

        try {
            MethodAnalysis result = new MethodAnalysis();
            Body body = method.getActiveBody();

            // Build control flow graph
            UnitGraph cfg = new ExceptionalUnitGraph(body);
            List<Unit> heads = new ArrayList<>(cfg.getHeads());

            if (heads.isEmpty()) {
                return null; // No entry points
            }

            // Get all paths through the method
            List<List<Unit>> allPaths = findAllPaths(cfg, heads.get(0));
            result.totalPaths = allPaths.size();

            // Process each path to extract events
            int pathId = 1;
            for (List<Unit> path : allPaths) {
                if (pathId > maxPathsPerMethod) {
                    System.out.println("    Warning: Method " + method.getSignature() +
                            " has more than " + maxPathsPerMethod + " paths. Truncating.");
                    break;
                }

                PathInfo pathInfo = new PathInfo();
                pathInfo.pathId = pathId++;

                // Process each unit in the path to extract allocations and method calls
                for (Unit unit : path) {
                    processUnit(unit, pathInfo);
                }

                // Only add the path if it has events
                if (!pathInfo.events.isEmpty()) {
                    result.paths.add(pathInfo);
                }
            }

            return result;
        } catch (Exception e) {
            System.err.println("Error analyzing method " + method.getSignature() + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        } finally {
            processedMethods.remove(method);
        }
    }

    /**
     * Finds all execution paths through a method using DFS
     */
    private List<List<Unit>> findAllPaths(UnitGraph cfg, Unit start) {
        List<List<Unit>> allPaths = new ArrayList<>();
        Set<String> pathSignatures = new HashSet<>(); // Use signatures to avoid duplicate paths

        // Initial path state
        PathState initialState = new PathState(start);
        initialState.visit(start);

        // Stack for DFS
        Stack<PathState> stack = new Stack<>();
        stack.push(initialState);

        while (!stack.isEmpty() && allPaths.size() < maxPathsPerMethod) {
            PathState current = stack.pop();
            Unit currentUnit = current.currentUnit;

            // Check if this is an exit point
            if (isExitPoint(currentUnit, cfg)) {
                List<Unit> completePath = new ArrayList<>(current.visitedUnits);

                // Create a signature for this path to check for duplicates
                String pathSignature = generatePathSignature(completePath);

                if (!pathSignatures.contains(pathSignature)) {
                    pathSignatures.add(pathSignature);
                    allPaths.add(completePath);
                }
                continue;
            }

            // Get successors
            List<Unit> successors = new ArrayList<>(cfg.getSuccsOf(currentUnit));

            // If this is a branch point with multiple successors
            if (successors.size() > 1) {
                // Process each branch
                for (Unit succ : successors) {
                    // Skip if we've visited this unit too many times (loop handling)
                    if (current.getVisitCount(succ) >= maxLoopIterations) {
                        continue;
                    }

                    PathState newState = new PathState(current);
                    newState.visit(succ);
                    stack.push(newState);
                }
            } else if (!successors.isEmpty()) {
                // Single successor
                Unit succ = successors.get(0);

                // Skip if we've visited this unit too many times (loop handling)
                if (current.getVisitCount(succ) < maxLoopIterations) {
                    current.visit(succ);
                    stack.push(current);
                }
            }
        }

        if (allPaths.size() >= maxPathsPerMethod) {
            System.out.println("    Reached maximum path count for method");
        }

        return allPaths;
    }

    /**
     * Generate a signature for a path to identify duplicates
     */
    private String generatePathSignature(List<Unit> path) {
        StringBuilder sb = new StringBuilder();
        for (Unit unit : path) {
            // Use hashcode of each unit to keep the signature manageable
            sb.append(unit.hashCode()).append("_");
        }
        return sb.toString();
    }

    /**
     * Checks if a unit is an exit point in the CFG
     */
    private boolean isExitPoint(Unit unit, UnitGraph cfg) {
        return cfg.getTails().contains(unit) ||
                unit instanceof ReturnStmt ||
                unit instanceof ReturnVoidStmt ||
                unit instanceof ThrowStmt;
    }

    /**
     * Process a single unit in a path to extract events
     */
    private void processUnit(Unit unit, PathInfo pathInfo) {
        // Check for allocations
        if (unit instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) unit;
            Value rightOp = assign.getRightOp();

            // Check for object allocations
            if (rightOp instanceof NewExpr) {
                NewExpr newExpr = (NewExpr) rightOp;
                String allocType = newExpr.getBaseType().toString();
                pathInfo.events.add(new AllocationEvent(allocType));
            } else if (rightOp instanceof NewArrayExpr) {
                NewArrayExpr newArrayExpr = (NewArrayExpr) rightOp;
                String allocType = newArrayExpr.getBaseType().toString() + "[]";
                pathInfo.events.add(new AllocationEvent(allocType));
            } else if (rightOp instanceof NewMultiArrayExpr) {
                NewMultiArrayExpr newArrayExpr = (NewMultiArrayExpr) rightOp;
                String allocType = newArrayExpr.getBaseType().toString() + "[][]";
                pathInfo.events.add(new AllocationEvent(allocType));
            }

            // Check for method calls in assignments
            if (rightOp instanceof InvokeExpr) {
                InvokeExpr invoke = (InvokeExpr) rightOp;
                SootMethod calledMethod = invoke.getMethod();
                pathInfo.events.add(new MethodCallEvent(calledMethod.getSignature()));
            }
        }

        // Check for direct method invocations
        if (unit instanceof InvokeStmt) {
            InvokeExpr invoke = ((InvokeStmt) unit).getInvokeExpr();
            SootMethod calledMethod = invoke.getMethod();
            pathInfo.events.add(new MethodCallEvent(calledMethod.getSignature()));
        }
    }

    /**
     * Writes the analysis results to a JSON file
     */
    private void writeAnalysisToJson(DexFileAnalysis analysis, String dexFileName) {
        try {
            // Create output directory if it doesn't exist
            File outputDir = new File(outputPath);
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }

            // Create output file
            String outputFileName = dexFileName + "_paths.json";
            File outputFile = new File(outputDir, outputFileName);

            // Use Gson to write JSON
            Gson gson = new GsonBuilder()
                    .setPrettyPrinting()
                    .disableHtmlEscaping()
                    .create();

            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(gson.toJson(analysis));
            }

            System.out.println("Path analysis for " + dexFileName + " saved to: " + outputFile.getAbsolutePath());

        } catch (IOException e) {
            System.err.println("Error writing analysis to JSON: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
