package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Detects dangerous API usage in Android applications by scanning loaded Soot
 * methods
 * against a configurable database of known dangerous APIs organized by threat
 * categories.
 */
public class DangerousApiDetector {

    private final Map<String, DangerousApiCategory> apiCategories;
    private final Map<String, String> signatureToCategory;
    private final Set<String> allDangerousSignatures;
    private final Gson gson;

    public DangerousApiDetector() {
        this.apiCategories = new HashMap<>();
        this.signatureToCategory = new HashMap<>();
        this.allDangerousSignatures = new HashSet<>();
        this.gson = new Gson();
    }

    /**
     * Load dangerous API configuration from JSON file
     */
    public void loadDangerousApiConfig(String configPath) throws IOException {
        System.out.println("Loading dangerous API configuration from: " + configPath);

        String jsonContent = new String(Files.readAllBytes(Paths.get(configPath)));
        JsonObject root = gson.fromJson(jsonContent, JsonObject.class);

        JsonObject categories = root.getAsJsonObject("api_categories");

        for (Map.Entry<String, JsonElement> categoryEntry : categories.entrySet()) {
            String categoryName = categoryEntry.getKey();
            JsonObject categoryData = categoryEntry.getValue().getAsJsonObject();

            DangerousApiCategory category = new DangerousApiCategory(
                    categoryName,
                    categoryData.get("description").getAsString(),
                    categoryData.get("severity").getAsString());

            JsonArray apiArray = categoryData.getAsJsonArray("apis");
            for (JsonElement apiElement : apiArray) {
                String apiSignature = apiElement.getAsString();
                category.addApiSignature(apiSignature);
                signatureToCategory.put(apiSignature, categoryName);
                allDangerousSignatures.add(apiSignature);
            }

            apiCategories.put(categoryName, category);
        }

        System.out.println("Loaded " + allDangerousSignatures.size() + " dangerous APIs across " +
                apiCategories.size() + " categories");

        // Print category summary
        for (DangerousApiCategory category : apiCategories.values()) {
            System.out.println("  " + category.getName() + " (" + category.getSeverity() + "): " +
                    category.getApiSignatures().size() + " APIs");
        }
    }

    /**
     * Scan the loaded Soot Scene for dangerous APIs present in the APK
     */
    public DangerousApiScanResult scanLoadedMethods() {
        System.out.println("\n=== SCANNING APK FOR DANGEROUS APIS ===");

        DangerousApiScanResult result = new DangerousApiScanResult();
        Set<String> foundSignatures = new HashSet<>();

        // Scan all application classes
        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.hasActiveBody()) {
                    scanMethodForDangerousApis(method, foundSignatures);
                }
            }
        }

        // Organize found APIs by category
        for (String signature : foundSignatures) {
            String category = signatureToCategory.get(signature);
            if (category != null) {
                try {
                    SootMethod dangerousMethod = Scene.v().getMethod(signature);
                    result.addFoundApi(category, dangerousMethod, signature);
                } catch (RuntimeException e) {
                    // Method might not be directly accessible, but we found a call to it
                    result.addFoundApiSignature(category, signature);
                }
            }
        }

        System.out.println("Dangerous API scan complete:");
        System.out.println("  Total dangerous APIs found: " + foundSignatures.size());
        for (Map.Entry<String, List<SootMethod>> entry : result.getFoundApisByCategory().entrySet()) {
            System.out.println("    " + entry.getKey() + ": " + entry.getValue().size() + " APIs");
        }

        return result;
    }

    /**
     * Scan a single method for dangerous API calls
     */
    private void scanMethodForDangerousApis(SootMethod method, Set<String> foundSignatures) {
        Body body = method.getActiveBody();

        for (Unit unit : body.getUnits()) {
            if (unit instanceof InvokeStmt) {
                InvokeExpr invoke = ((InvokeStmt) unit).getInvokeExpr();
                checkInvokeExpression(invoke, foundSignatures);
            } else if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                if (assign.getRightOp() instanceof InvokeExpr) {
                    checkInvokeExpression((InvokeExpr) assign.getRightOp(), foundSignatures);
                }
            }
        }
    }

    /**
     * Check if an invoke expression matches any dangerous API
     */
    private void checkInvokeExpression(InvokeExpr invoke, Set<String> foundSignatures) {
        String methodSignature = invoke.getMethod().getSignature();

        if (allDangerousSignatures.contains(methodSignature)) {
            foundSignatures.add(methodSignature);
            System.out.println("    Found dangerous API: " + methodSignature);
        }
    }

    /**
     * Get APIs by severity level
     */
    public List<SootMethod> getApisBySeverity(DangerousApiScanResult scanResult, String severity) {
        List<SootMethod> methods = new ArrayList<>();

        for (Map.Entry<String, DangerousApiCategory> entry : apiCategories.entrySet()) {
            if (entry.getValue().getSeverity().equals(severity)) {
                String categoryName = entry.getKey();
                List<SootMethod> categoryMethods = scanResult.getFoundApisByCategory().get(categoryName);
                if (categoryMethods != null) {
                    methods.addAll(categoryMethods);
                }
            }
        }

        return methods;
    }

    /**
     * Get all found dangerous APIs sorted by priority
     */
    public List<SootMethod> getPrioritizedDangerousApis(DangerousApiScanResult scanResult) {
        List<SootMethod> prioritized = new ArrayList<>();

        // Add CRITICAL APIs first
        prioritized.addAll(getApisBySeverity(scanResult, "CRITICAL"));
        // Then HIGH severity
        prioritized.addAll(getApisBySeverity(scanResult, "HIGH"));
        // Finally MEDIUM severity
        prioritized.addAll(getApisBySeverity(scanResult, "MEDIUM"));

        return prioritized;
    }

    /**
     * Generate scan summary for reporting
     */
    public String generateScanSummary(DangerousApiScanResult scanResult) {
        StringBuilder summary = new StringBuilder();
        summary.append("DANGEROUS API SCAN SUMMARY\n");
        summary.append("==========================\n");

        int totalFound = scanResult.getTotalFoundApis();
        summary.append("Total dangerous APIs found: ").append(totalFound).append("\n\n");

        for (String categoryName : apiCategories.keySet()) {
            DangerousApiCategory category = apiCategories.get(categoryName);
            List<SootMethod> foundInCategory = scanResult.getFoundApisByCategory().get(categoryName);
            int count = foundInCategory != null ? foundInCategory.size() : 0;

            summary.append(String.format("%-25s (%s): %d APIs\n",
                    categoryName, category.getSeverity(), count));

            if (foundInCategory != null) {
                for (SootMethod method : foundInCategory) {
                    summary.append("  - ").append(method.getSignature()).append("\n");
                }
            }
        }

        return summary.toString();
    }

    // Getters
    public Map<String, DangerousApiCategory> getApiCategories() {
        return Collections.unmodifiableMap(apiCategories);
    }

    public Set<String> getAllDangerousSignatures() {
        return Collections.unmodifiableSet(allDangerousSignatures);
    }
}

/**
 * Represents a category of dangerous APIs
 */
class DangerousApiCategory {
    private final String name;
    private final String description;
    private final String severity;
    private final Set<String> apiSignatures;

    public DangerousApiCategory(String name, String description, String severity) {
        this.name = name;
        this.description = description;
        this.severity = severity;
        this.apiSignatures = new HashSet<>();
    }

    public void addApiSignature(String signature) {
        apiSignatures.add(signature);
    }

    // Getters
    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    public Set<String> getApiSignatures() {
        return Collections.unmodifiableSet(apiSignatures);
    }
}

/**
 * Results of dangerous API scanning
 */
class DangerousApiScanResult {
    private final Map<String, List<SootMethod>> foundApisByCategory;
    private final Map<String, List<String>> foundSignaturesByCategory;

    public DangerousApiScanResult() {
        this.foundApisByCategory = new HashMap<>();
        this.foundSignaturesByCategory = new HashMap<>();
    }

    public void addFoundApi(String category, SootMethod method, String signature) {
        foundApisByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(method);
        foundSignaturesByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(signature);
    }

    public void addFoundApiSignature(String category, String signature) {
        foundSignaturesByCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(signature);
    }

    public int getTotalFoundApis() {
        return foundApisByCategory.values().stream().mapToInt(List::size).sum();
    }

    public Map<String, List<SootMethod>> getFoundApisByCategory() {
        return foundApisByCategory;
    }

    public Map<String, List<String>> getFoundSignaturesByCategory() {
        return foundSignaturesByCategory;
    }
}