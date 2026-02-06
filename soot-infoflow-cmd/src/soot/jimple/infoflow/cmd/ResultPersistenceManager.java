package soot.jimple.infoflow.cmd;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Manages persistence of analysis results to structured JSON files and
 * directories.
 * Provides functionality for saving, loading, and organizing APK analysis
 * results.
 */
public class ResultPersistenceManager {

    private final Gson gson;
    private final String baseOutputDirectory;

    public ResultPersistenceManager(String baseOutputDirectory) {
        this.baseOutputDirectory = baseOutputDirectory;
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .serializeNulls()
                .disableHtmlEscaping()
                .create();

        // Create base output directory if it doesn't exist
        createDirectory(baseOutputDirectory);
    }

    /**
     * Save complete APK analysis results to structured directory
     */
    public void saveApkAnalysisResult(ApkAnalysisResult apkResult) throws IOException {
        if (apkResult == null) {
            throw new IllegalArgumentException("APK analysis result cannot be null");
        }

        String apkName = sanitizeFileName(apkResult.getApkMetadata().getApkName().replace(".apk", ""));
        String apkOutputDir = baseOutputDirectory + "/" + apkName + "/";

        // Create APK-specific directory structure
        createApkDirectoryStructure(apkOutputDir);

        // Save main APK analysis summary
        String summaryPath = apkOutputDir + "analysis_summary.json";
        saveJsonFile(apkResult, summaryPath);

        // Save dangerous APIs summary
        String dangerousApisSummaryPath = apkOutputDir + "dangerous_apis_found.json";
        saveDangerousApisSummary(apkResult.getDangerousApisFound(), dangerousApisSummaryPath);

        // Save individual dangerous API analyses
        String constraintAnalysisDir = apkOutputDir + "constraint_analysis/";
        createDirectory(constraintAnalysisDir);

        for (DangerousApiAnalysisResult apiResult : apkResult.getDangerousApisFound()) {
            saveDangerousApiAnalysis(apiResult, constraintAnalysisDir);
        }

        System.out.println("✅ Saved analysis results for " + apkName + " to: " + apkOutputDir);
    }

    /**
     * Save individual dangerous API analysis result
     */
    private void saveDangerousApiAnalysis(DangerousApiAnalysisResult apiResult, String outputDir) throws IOException {
        // Create filename from method signature
        String methodName = extractMethodNameFromSignature(apiResult.getMethodSignature());
        String fileName = sanitizeFileName(methodName + "_" + apiResult.getApiCategory()) + ".json";
        String filePath = outputDir + fileName;

        saveJsonFile(apiResult, filePath);

        // Also save a human-readable summary
        String summaryPath = outputDir + sanitizeFileName(methodName + "_" + apiResult.getApiCategory())
                + "_summary.txt";
        saveHumanReadableSummary(apiResult, summaryPath);
    }

    /**
     * Save dangerous APIs summary (list format for easy analysis)
     */
    private void saveDangerousApisSummary(List<DangerousApiAnalysisResult> dangerousApis, String filePath)
            throws IOException {
        Map<String, Object> summary = new HashMap<>();
        summary.put("total_dangerous_apis", dangerousApis.size());
        summary.put("analysis_timestamp",
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));

        // Organize by category
        Map<String, List<String>> categorizedApis = new HashMap<>();
        Map<String, Integer> categoryStats = new HashMap<>();

        for (DangerousApiAnalysisResult apiResult : dangerousApis) {
            String category = apiResult.getApiCategory();
            categorizedApis.computeIfAbsent(category, k -> new ArrayList<>())
                    .add(apiResult.getMethodSignature());
            categoryStats.merge(category, 1, Integer::sum);
        }

        summary.put("apis_by_category", categorizedApis);
        summary.put("category_statistics", categoryStats);
        summary.put("detailed_results", dangerousApis);

        saveJsonFile(summary, filePath);
    }

    /**
     * Save human-readable summary of dangerous API analysis
     */
    private void saveHumanReadableSummary(DangerousApiAnalysisResult apiResult, String filePath) throws IOException {
        StringBuilder summary = new StringBuilder();
        summary.append("=".repeat(80)).append("\n");
        summary.append("DANGEROUS API ANALYSIS SUMMARY\n");
        summary.append("=".repeat(80)).append("\n\n");

        summary.append("Method Signature: ").append(apiResult.getMethodSignature()).append("\n");
        summary.append("API Category: ").append(apiResult.getApiCategory()).append("\n");
        summary.append("Severity Level: ").append(apiResult.getSeverityLevel()).append("\n");
        summary.append("Analysis Status: ").append(apiResult.getAnalysisStatus()).append("\n");

        if (apiResult.getAnalysisErrorMessage() != null) {
            summary.append("Error Message: ").append(apiResult.getAnalysisErrorMessage()).append("\n");
        }

        summary.append("\n");
        summary.append("Call Chains Found: ").append(apiResult.getCallChains().size()).append("\n");
        summary.append("Constraints Found: ").append(apiResult.getConstraintsFound().size()).append("\n");

        // Call chains details
        if (!apiResult.getCallChains().isEmpty()) {
            summary.append("\n").append("=".repeat(40)).append("\n");
            summary.append("CALL CHAINS\n");
            summary.append("=".repeat(40)).append("\n");

            for (int i = 0; i < apiResult.getCallChains().size(); i++) {
                DangerousApiAnalysisResult.MethodCallChain chain = apiResult.getCallChains().get(i);
                summary.append("\nCall Chain ").append(i + 1).append(" (").append(chain.getChainId()).append("):\n");
                summary.append("  Path Type: ").append(chain.getPathType()).append("\n");
                summary.append("  Reachable: ").append(chain.isReachable()).append("\n");
                summary.append("  Method Sequence:\n");

                for (int j = 0; j < chain.getMethodSequence().size(); j++) {
                    summary.append("    ").append(j + 1).append(". ").append(chain.getMethodSequence().get(j))
                            .append("\n");
                }
            }
        }

        // Constraints details
        if (!apiResult.getConstraintsFound().isEmpty()) {
            summary.append("\n").append("=".repeat(40)).append("\n");
            summary.append("CONSTRAINTS\n");
            summary.append("=".repeat(40)).append("\n");

            for (int i = 0; i < apiResult.getConstraintsFound().size(); i++) {
                DangerousApiAnalysisResult.ConstraintSpecification constraint = apiResult.getConstraintsFound().get(i);
                summary.append("\nConstraint ").append(i + 1).append(" (").append(constraint.getConstraintId())
                        .append("):\n");
                summary.append("  Associated Call Chain: ").append(constraint.getAssociatedCallChain()).append("\n");
                summary.append("  Complexity: ").append(constraint.getConstraintComplexity()).append(" conditions\n");

                if (constraint.getBooleanLogicFormat() != null) {
                    summary.append("  Boolean Logic: ").append(constraint.getBooleanLogicFormat()).append("\n");
                }
                if (constraint.getBusinessContextFormat() != null) {
                    summary.append("  Business Context: ").append(constraint.getBusinessContextFormat()).append("\n");
                }
                if (constraint.getTechnicalDetailsFormat() != null) {
                    summary.append("  Technical Details: ").append(constraint.getTechnicalDetailsFormat()).append("\n");
                }
            }
        }

        Files.write(Paths.get(filePath), summary.toString().getBytes());
    }

    /**
     * Load existing APK analysis result
     */
    public ApkAnalysisResult loadApkAnalysisResult(String apkName) throws IOException {
        String sanitizedApkName = sanitizeFileName(apkName.replace(".apk", ""));
        String summaryPath = baseOutputDirectory + "/" + sanitizedApkName + "/analysis_summary.json";

        if (!Files.exists(Paths.get(summaryPath))) {
            return null;
        }

        String jsonContent = new String(Files.readAllBytes(Paths.get(summaryPath)));
        return gson.fromJson(jsonContent, ApkAnalysisResult.class);
    }

    /**
     * Check if APK has already been analyzed
     */
    public boolean hasExistingAnalysis(String apkName) {
        String sanitizedApkName = sanitizeFileName(apkName.replace(".apk", ""));
        String summaryPath = baseOutputDirectory + "/" + sanitizedApkName + "/analysis_summary.json";
        return Files.exists(Paths.get(summaryPath));
    }

    /**
     * Create directory structure for APK analysis results
     */
    private void createApkDirectoryStructure(String apkOutputDir) {
        createDirectory(apkOutputDir);
        createDirectory(apkOutputDir + "constraint_analysis/");
        createDirectory(apkOutputDir + "call_graphs/");
        createDirectory(apkOutputDir + "llm_interactions/");
    }

    /**
     * Create directory if it doesn't exist
     */
    private void createDirectory(String dirPath) {
        try {
            Files.createDirectories(Paths.get(dirPath));
        } catch (IOException e) {
            System.err.println("WARNING: Could not create directory " + dirPath + ": " + e.getMessage());
        }
    }

    /**
     * Save object as JSON file
     */
    private void saveJsonFile(Object object, String filePath) throws IOException {
        String jsonContent = gson.toJson(object);
        Files.write(Paths.get(filePath), jsonContent.getBytes());
    }

    /**
     * Sanitize filename for file system compatibility
     */
    private String sanitizeFileName(String fileName) {
        return fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /**
     * Extract method name from full signature for filename
     */
    private String extractMethodNameFromSignature(String methodSignature) {
        try {
            // Extract method name from signature like "<class: returnType
            // methodName(params)>"
            int colonIndex = methodSignature.indexOf(": ");
            int parenIndex = methodSignature.indexOf("(", colonIndex);

            if (colonIndex != -1 && parenIndex != -1) {
                String methodPart = methodSignature.substring(colonIndex + 2, parenIndex);
                int spaceIndex = methodPart.lastIndexOf(" ");
                return spaceIndex != -1 ? methodPart.substring(spaceIndex + 1) : methodPart;
            }
        } catch (Exception e) {
            // Fallback to hash-based name if parsing fails
        }

        return "method_" + Math.abs(methodSignature.hashCode());
    }

    /**
     * Generate batch summary across all analyzed APKs
     */
    public void generateBatchSummary() throws IOException {
        // TODO: Implement cross-APK analysis summary
        String summaryPath = baseOutputDirectory + "/batch_summary.json";
        Map<String, Object> batchSummary = new HashMap<>();
        batchSummary.put("generated_at",
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        batchSummary.put("total_apks_analyzed", "TODO");

        saveJsonFile(batchSummary, summaryPath);
    }
}