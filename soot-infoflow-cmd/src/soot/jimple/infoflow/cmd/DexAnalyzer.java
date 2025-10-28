package soot.jimple.infoflow.cmd;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import soot.Body;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.Stmt;
import soot.options.Options;

public class DexAnalyzer {
    private String dexFolderPath;
    private String outputPath;

    // Map to store method to allocation mapping
    private Map<SootMethod, Set<String>> methodToAllocations;

    // Set to track methods being processed (to handle recursion)
    private Set<SootMethod> processingStack;

    // Save original Soot state
    private Map<String, Object> originalSootState;

    public DexAnalyzer(String dexFolderPath, String outputPath) {
        this.dexFolderPath = dexFolderPath;
        this.outputPath = outputPath;
        this.methodToAllocations = new HashMap<>();
        this.processingStack = new HashSet<>();
        this.originalSootState = new HashMap<>();
    }

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
        originalSootState.put("processDir", Options.v().process_dir());
        originalSootState.put("androidJars", Options.v().android_jars());
        originalSootState.put("srcPrec", Options.v().src_prec());
        originalSootState.put("allowPhantomRefs", Options.v().allow_phantom_refs());
        originalSootState.put("wholeProgram", Options.v().whole_program());
    }

    private void restoreSootState() {
        // Restore the key settings we changed
        Options.v().set_process_dir((List<String>) originalSootState.get("processDir"));
        Options.v().set_android_jars((String) originalSootState.get("androidJars"));
        Options.v().set_src_prec((Integer) originalSootState.get("srcPrec"));
        Options.v().set_allow_phantom_refs((Boolean) originalSootState.get("allowPhantomRefs"));
        Options.v().set_whole_program((Boolean) originalSootState.get("wholeProgram"));
    }

    private void analyzeSingleDexFile(File dexFile) {
        try {
            // Clear existing allocation data
            methodToAllocations.clear();
            processingStack.clear();

            // Configure Soot for this specific DEX file
            Options.v().set_process_dir(Collections.singletonList(dexFile.getAbsolutePath()));
            Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_output_format(Options.output_format_none);
            Options.v().set_allow_phantom_refs(true);
            Options.v().set_ignore_resolution_errors(true);
            Options.v().set_whole_program(true); // Set whole program mode to true

            // Load classes from DEX
            Scene.v().loadNecessaryClasses();
            Scene.v().getOrMakeFastHierarchy(); // Ensures FastHierarchy is initialized
            PackManager.v().runPacks();

            // Get all loaded classes
            List<SootClass> classList = new ArrayList<>();
            for (SootClass sc : Scene.v().getClasses()) {
                if (!sc.isPhantom() && !sc.isPhantomClass()) {
                    classList.add(sc);
                }
            }

            // Process all methods in all classes
            for (SootClass sc : classList) {
                for (SootMethod method : sc.getMethods()) {
                    if (method.hasActiveBody()) {
                        analyzeMethodAllocations(method);
                    }
                }
            }

            // Write JSON model for this DEX file
            writeJsonModel(dexFile.getName() + "_model.json");

        } catch (Exception e) {
            System.err.println("Error analyzing " + dexFile.getName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private Set<String> analyzeMethodAllocations(SootMethod method) {
        // Check cache first
        if (methodToAllocations.containsKey(method)) {
            return methodToAllocations.get(method);
        }

        // Check for recursion
        if (processingStack.contains(method)) {
            return new HashSet<>(); // Break recursion
        }

        // Mark as being processed
        processingStack.add(method);

        // Create result set
        Set<String> allocations = new HashSet<>();
        methodToAllocations.put(method, allocations);

        try {
            if (!method.hasActiveBody()) {
                return allocations;
            }

            Body body = method.getActiveBody();

            // Process all statements in the method
            for (Unit unit : body.getUnits()) {
                if (unit instanceof Stmt) {
                    Stmt stmt = (Stmt) unit;

                    // Check for direct allocations
                    if (stmt instanceof AssignStmt) {
                        AssignStmt assign = (AssignStmt) stmt;
                        Value rightOp = assign.getRightOp();

                        // Check for new expressions
                        if (rightOp instanceof NewExpr) {
                            NewExpr newExpr = (NewExpr) rightOp;
                            String allocType = newExpr.getBaseType().toString();
                            allocations.add(allocType);
                        } else if (rightOp instanceof NewArrayExpr) {
                            NewArrayExpr newExpr = (NewArrayExpr) rightOp;
                            String allocType = newExpr.getBaseType().toString() + "[]";
                            allocations.add(allocType);
                        } else if (rightOp instanceof NewMultiArrayExpr) {
                            NewMultiArrayExpr newExpr = (NewMultiArrayExpr) rightOp;
                            String allocType = newExpr.getBaseType().toString() + "[][]";
                            allocations.add(allocType);
                        }
                    }

                    // Check for method calls to recursively find allocations
                    if (stmt.containsInvokeExpr()) {
                        InvokeExpr invoke = stmt.getInvokeExpr();
                        SootClass declaringClass = invoke.getMethodRef().declaringClass();
                        Scene.v().forceResolve(declaringClass.getName(), SootClass.SIGNATURES);
                        SootMethod calledMethod = invoke.getMethod();

                        // Skip if already being processed (avoid recursion)
                        if (!processingStack.contains(calledMethod)) {
                            // Recursively analyze called method
                            Set<String> calleeAllocations = analyzeMethodAllocations(calledMethod);

                            // Add these allocations to current method
                            allocations.addAll(calleeAllocations);
                        }
                    }
                }
            }
        } finally {
            // Remove from processing stack
            processingStack.remove(method);
        }

        return allocations;
    }

    @SuppressWarnings("unchecked")
    private void writeJsonModel(String fileName) {
        try {
            File jsonFile = new File(outputPath, fileName);
            JsonObject rootObject = new JsonObject();

            // For each method with allocations
            for (Map.Entry<SootMethod, Set<String>> entry : methodToAllocations.entrySet()) {
                SootMethod method = entry.getKey();
                Set<String> allocations = entry.getValue();

                if (!allocations.isEmpty()) {
                    String methodSignature = method.getSignature();

                    // Create a formatted JSON array with one allocation per line
                    StringBuilder allocBuilder = new StringBuilder();
                    allocBuilder.append("[\n");

                    // Sort for consistency
                    List<String> sortedAllocs = new ArrayList<>(allocations);
                    Collections.sort(sortedAllocs);

                    for (int i = 0; i < sortedAllocs.size(); i++) {
                        allocBuilder.append("  \"").append(sortedAllocs.get(i)).append("\"");
                        if (i < sortedAllocs.size() - 1) {
                            allocBuilder.append(",");
                        }
                        allocBuilder.append("\n");
                    }
                    allocBuilder.append("]");

                    // Add to root object as a pre-formatted string
                    rootObject.addProperty(methodSignature, allocBuilder.toString());
                }
            }

            // GsonBuilder to pretty print JSON output
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // Write JSON to file with pretty formatting
            try (FileWriter writer = new FileWriter(jsonFile)) {
                writer.write(gson.toJson(rootObject)); // Pretty print with Gson
            }

            System.out.println("JSON model saved to: " + jsonFile.getAbsolutePath());

        } catch (IOException e) {
            System.err.println("Error writing JSON model: " + e.getMessage());
        }
    }

}