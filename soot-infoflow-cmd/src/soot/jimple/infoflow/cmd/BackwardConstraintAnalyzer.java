package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.stream.Collectors;
import java.io.*;
import java.nio.file.*;

/**
 * Main orchestrator for backward constraint analysis. Given a target method,
 * finds all execution paths and constraints that lead to its invocation.
 * 
 * Coordinates AllocationGraphAnalyzer, ConstraintExtractor, and
 * ConstraintPathBuilder
 * to perform comprehensive backward analysis from target method to entry
 * points.
 */
public class BackwardConstraintAnalyzer {
    private final AllocationGraphAnalyzer graphAnalyzer;
    private final ConstraintExtractor constraintExtractor;
    private final ConstraintPathBuilder pathBuilder;
    private final AnalysisConfig config;
    private final Map<SootMethod, List<ConstraintPath>> targetMethodToPaths;
    private final Set<SootMethod> analyzedTargets;
    private boolean initialized;

    public BackwardConstraintAnalyzer(AllocationGraphAnalyzer graphAnalyzer, AnalysisConfig config) {
        this.graphAnalyzer = graphAnalyzer;
        this.config = config;
        this.targetMethodToPaths = new HashMap<>();
        this.analyzedTargets = new HashSet<>();
        this.initialized = false;

        // Initialize constraint extractor with LLM configuration
        LLMConfig llmConfig = new LLMConfig(
                LLMProvider.OLLAMA,
                "",
                "codellama:7b");
        this.constraintExtractor = new ConstraintExtractor(llmConfig, true);

        // Initialize path builder
        this.pathBuilder = new ConstraintPathBuilder(graphAnalyzer, constraintExtractor);
    }

    /**
     * Initialize the analyzer (must be called before analysis)
     */
    public void initialize() {
        if (initialized) {
            return;
        }

        System.out.println("=== Initializing Backward Constraint Analyzer ===");

        // Ensure allocation graph analyzer is initialized
        if (graphAnalyzer.getCallGraph() == null) {
            System.out.println("Initializing AllocationGraphAnalyzer...");
            graphAnalyzer.initializeAnalysis();
            graphAnalyzer.analyze();
        }

        System.out.println("Analyzer initialization complete");
        System.out.println("Available methods: " + graphAnalyzer.getAnalyzedMethods().size());
        System.out.println("Call graph edges: " + graphAnalyzer.getCallGraph().size());

        initialized = true;
    }

    /**
     * Analyze constraints for a specific target method
     */
    public ConstraintAnalysisResult analyzeMethod(SootMethod targetMethod) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized. Call initialize() first.");
        }

        System.out.println("\n=== Analyzing Target Method ===");
        System.out.println("Target: " + targetMethod.getSignature());

        long startTime = System.currentTimeMillis();

        try {
            // Build constraint paths to target method
            List<ConstraintPath> paths = pathBuilder.buildPathsToTarget(targetMethod);

            // Create analysis result
            ConstraintAnalysisResult result = new ConstraintAnalysisResult(
                    targetMethod, paths, System.currentTimeMillis() - startTime);

            // Cache result
            targetMethodToPaths.put(targetMethod, paths);
            analyzedTargets.add(targetMethod);

            // Generate summary
            generateAnalysisSummary(result);

            return result;

        } catch (Exception e) {
            System.err.println("Error analyzing method " + targetMethod.getSignature() + ": " + e.getMessage());
            e.printStackTrace();

            return new ConstraintAnalysisResult(
                    targetMethod, new ArrayList<>(), System.currentTimeMillis() - startTime,
                    "Analysis failed: " + e.getMessage());
        }
    }

    /**
     * Analyze constraints for multiple target methods
     */
    public Map<SootMethod, ConstraintAnalysisResult> analyzeMethods(Collection<SootMethod> targetMethods) {
        Map<SootMethod, ConstraintAnalysisResult> results = new HashMap<>();

        System.out.println("\n=== Batch Analysis of " + targetMethods.size() + " Methods ===");

        int completed = 0;
        for (SootMethod method : targetMethods) {
            System.out.println("Progress: " + (++completed) + "/" + targetMethods.size());

            ConstraintAnalysisResult result = analyzeMethod(method);
            results.put(method, result);

            // Optional: save intermediate results
            if (config.isSaveIntermediateResults()) {
                saveResultToFile(result, config.getOutputDirectory());
            }
        }

        return results;
    }

    /**
     * Find target methods by name pattern
     */
    public List<SootMethod> findMethodsByName(String namePattern) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized");
        }

        return graphAnalyzer.getAnalyzedMethods().stream()
                .filter(method -> method.getName().contains(namePattern))
                .collect(Collectors.toList());
    }

    /**
     * Find target methods in specific class
     */
    public List<SootMethod> findMethodsInClass(String className) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized");
        }

        try {
            SootClass targetClass = Scene.v().getSootClass(className);
            return graphAnalyzer.getAnalyzedMethods().stream()
                    .filter(method -> method.getDeclaringClass().equals(targetClass))
                    .collect(Collectors.toList());
        } catch (RuntimeException e) {
            System.err.println("Class not found: " + className);
            return new ArrayList<>();
        }
    }

    /**
     * Get all analyzed target methods
     */
    public Set<SootMethod> getAnalyzedTargets() {
        return Collections.unmodifiableSet(analyzedTargets);
    }

    /**
     * Get paths for a previously analyzed method
     */
    public List<ConstraintPath> getPathsForMethod(SootMethod method) {
        return targetMethodToPaths.getOrDefault(method, new ArrayList<>());
    }

    /**
     * Generate comprehensive analysis report
     */
    public AnalysisReport generateReport(Collection<ConstraintAnalysisResult> results) {
        System.out.println("\n=== Generating Analysis Report ===");

        AnalysisReport report = new AnalysisReport();

        // Overall statistics
        report.totalMethods = results.size();
        report.successfulAnalyses = (int) results.stream().filter(r -> r.isSuccessful()).count();
        report.totalPaths = results.stream().mapToInt(r -> r.getPaths().size()).sum();
        report.totalValidPaths = results.stream()
                .flatMap(r -> r.getPaths().stream())
                .mapToInt(p -> p.isValidPath() ? 1 : 0)
                .sum();

        // Constraint statistics
        Map<ConstraintType, Integer> constraintCounts = new HashMap<>();
        Map<PathType, Integer> pathTypeCounts = new HashMap<>();

        for (ConstraintAnalysisResult result : results) {
            for (ConstraintPath path : result.getPaths()) {
                // Count constraint types
                for (Constraint constraint : path.getConstraints()) {
                    constraintCounts.merge(constraint.getType(), 1, Integer::sum);
                }

                // Count path types
                pathTypeCounts.merge(path.getPathType(), 1, Integer::sum);
            }
        }

        report.constraintTypeCounts = constraintCounts;
        report.pathTypeCounts = pathTypeCounts;

        // Performance statistics
        report.averageAnalysisTime = results.stream()
                .mapToLong(ConstraintAnalysisResult::getAnalysisTimeMs)
                .average()
                .orElse(0.0);

        // Method complexity analysis
        report.methodComplexityStats = analyzeMethodComplexity(results);

        return report;
    }

    /**
     * Save analysis results to files
     */
    public void saveResults(Collection<ConstraintAnalysisResult> results, String outputDirectory) {
        try {
            Path outputPath = Paths.get(outputDirectory);
            Files.createDirectories(outputPath);

            // Save individual method results
            for (ConstraintAnalysisResult result : results) {
                saveResultToFile(result, outputDirectory);
            }

            // Save summary report
            AnalysisReport report = generateReport(results);
            saveReportToFile(report, outputPath.resolve("analysis_report.txt").toString());

            // Save constraint paths in different formats
            savePathsAsJson(results, outputPath.resolve("constraint_paths.json").toString());
            savePathsAsCSV(results, outputPath.resolve("constraint_summary.csv").toString());

            System.out.println("Results saved to: " + outputDirectory);

        } catch (IOException e) {
            System.err.println("Error saving results: " + e.getMessage());
        }
    }

    /**
     * Generate analysis summary for console output
     */
    private void generateAnalysisSummary(ConstraintAnalysisResult result) {
        System.out.println("\n--- Analysis Summary ---");
        System.out.println("Target Method: " + result.getTargetMethod().getSignature());
        System.out.println("Analysis Time: " + result.getAnalysisTimeMs() + "ms");
        System.out.println("Total Paths Found: " + result.getPaths().size());

        long validPaths = result.getPaths().stream().filter(ConstraintPath::isValidPath).count();
        System.out.println("Valid Paths: " + validPaths);
        System.out.println("Invalid Paths: " + (result.getPaths().size() - validPaths));

        if (!result.getPaths().isEmpty()) {
            // Show constraint statistics
            Map<ConstraintType, Long> constraintStats = result.getPaths().stream()
                    .flatMap(path -> path.getConstraints().stream())
                    .collect(Collectors.groupingBy(Constraint::getType, Collectors.counting()));

            System.out.println("Constraint Types:");
            constraintStats.forEach((type, count) -> System.out.println("  " + type + ": " + count));

            // Show sample paths
            System.out.println("\nSample Paths:");
            result.getPaths().stream()
                    .filter(ConstraintPath::isValidPath)
                    .limit(3)
                    .forEach(path -> System.out.println("  " + path.getPathSummary()));
        }

        if (!result.isSuccessful()) {
            System.out.println("Error: " + result.getErrorMessage());
        }

        System.out.println("--- End Summary ---\n");
    }

    /**
     * Save individual result to file
     */
    private void saveResultToFile(ConstraintAnalysisResult result, String outputDirectory) {
        try {
            Path outputPath = Paths.get(outputDirectory);
            Files.createDirectories(outputPath);

            String fileName = sanitizeFileName(result.getTargetMethod().getName()) + "_constraints.txt";
            Path filePath = outputPath.resolve(fileName);

            try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(filePath))) {
                writeResultToWriter(result, writer);
            }

        } catch (IOException e) {
            System.err.println("Error saving result for method " +
                    result.getTargetMethod().getName() + ": " + e.getMessage());
        }
    }

    /**
     * Write result to writer
     */
    private void writeResultToWriter(ConstraintAnalysisResult result, PrintWriter writer) {
        writer.println("Constraint Analysis Result");
        writer.println("=========================");
        writer.println("Target Method: " + result.getTargetMethod().getSignature());
        writer.println("Analysis Time: " + result.getAnalysisTimeMs() + "ms");
        writer.println("Success: " + result.isSuccessful());

        if (!result.isSuccessful()) {
            writer.println("Error: " + result.getErrorMessage());
            return;
        }

        writer.println("Total Paths: " + result.getPaths().size());
        writer.println();

        // Write each path
        for (int i = 0; i < result.getPaths().size(); i++) {
            ConstraintPath path = result.getPaths().get(i);
            writer.println("Path " + (i + 1) + ":");
            writer.println(path.getPathDescription());
            writer.println();
        }
    }

    /**
     * Analyze method complexity
     */
    private Map<String, Object> analyzeMethodComplexity(Collection<ConstraintAnalysisResult> results) {
        Map<String, Object> stats = new HashMap<>();

        List<Integer> pathCounts = results.stream()
                .mapToInt(r -> r.getPaths().size())
                .boxed()
                .collect(Collectors.toList());

        List<Integer> constraintCounts = results.stream()
                .flatMap(r -> r.getPaths().stream())
                .mapToInt(ConstraintPath::getConstraintCount)
                .boxed()
                .collect(Collectors.toList());

        stats.put("avgPathsPerMethod", pathCounts.stream().mapToInt(Integer::intValue).average().orElse(0.0));
        stats.put("maxPathsPerMethod", pathCounts.stream().mapToInt(Integer::intValue).max().orElse(0));
        stats.put("avgConstraintsPerPath", constraintCounts.stream().mapToInt(Integer::intValue).average().orElse(0.0));
        stats.put("maxConstraintsPerPath", constraintCounts.stream().mapToInt(Integer::intValue).max().orElse(0));

        return stats;
    }

    /**
     * Save paths as JSON
     */
    private void savePathsAsJson(Collection<ConstraintAnalysisResult> results, String filePath) {
        // Simplified JSON export - would need proper JSON library for full
        // implementation
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(filePath)))) {
            writer.println("{ \"constraint_analysis_results\": [");

            boolean first = true;
            for (ConstraintAnalysisResult result : results) {
                if (!first)
                    writer.println(",");
                writeResultAsJson(result, writer);
                first = false;
            }

            writer.println("\n]}");
        } catch (IOException e) {
            System.err.println("Error saving JSON: " + e.getMessage());
        }
    }

    /**
     * Write result as JSON (simplified)
     */
    private void writeResultAsJson(ConstraintAnalysisResult result, PrintWriter writer) {
        writer.println("  {");
        writer.println("    \"method\": \"" + escapeJson(result.getTargetMethod().getSignature()) + "\",");
        writer.println("    \"analysis_time_ms\": " + result.getAnalysisTimeMs() + ",");
        writer.println("    \"path_count\": " + result.getPaths().size() + ",");
        writer.println("    \"paths\": [");

        for (int i = 0; i < result.getPaths().size(); i++) {
            ConstraintPath path = result.getPaths().get(i);
            if (i > 0)
                writer.println(",");
            writer.println("      {");
            writer.println("        \"id\": \"" + path.getPathId() + "\",");
            writer.println("        \"valid\": " + path.isValidPath() + ",");
            writer.println("        \"constraint_count\": " + path.getConstraintCount());
            writer.println("      }");
        }

        writer.println("    ]");
        writer.println("  }");
    }

    /**
     * Save paths as CSV summary
     */
    private void savePathsAsCSV(Collection<ConstraintAnalysisResult> results, String filePath) {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(filePath)))) {
            // CSV header
            writer.println("Method,Analysis_Time_MS,Total_Paths,Valid_Paths,Invalid_Paths,Avg_Constraints");

            for (ConstraintAnalysisResult result : results) {
                List<ConstraintPath> paths = result.getPaths();
                long validPaths = paths.stream().filter(ConstraintPath::isValidPath).count();
                double avgConstraints = paths.stream().mapToInt(ConstraintPath::getConstraintCount).average()
                        .orElse(0.0);

                writer.printf("%s,%d,%d,%d,%d,%.2f%n",
                        escapeCSV(result.getTargetMethod().getSignature()),
                        result.getAnalysisTimeMs(),
                        paths.size(),
                        validPaths,
                        paths.size() - validPaths,
                        avgConstraints);
            }
        } catch (IOException e) {
            System.err.println("Error saving CSV: " + e.getMessage());
        }
    }

    /**
     * Save report to file
     */
    private void saveReportToFile(AnalysisReport report, String filePath) {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(filePath)))) {
            writer.println("Backward Constraint Analysis Report");
            writer.println("==================================");
            writer.println();
            writer.println("Overall Statistics:");
            writer.println("  Total Methods Analyzed: " + report.totalMethods);
            writer.println("  Successful Analyses: " + report.successfulAnalyses);
            writer.println("  Total Paths Found: " + report.totalPaths);
            writer.println("  Valid Paths: " + report.totalValidPaths);
            writer.printf("  Average Analysis Time: %.2f ms%n", report.averageAnalysisTime);
            writer.println();

            writer.println("Constraint Type Distribution:");
            report.constraintTypeCounts.forEach((type, count) -> writer.println("  " + type + ": " + count));
            writer.println();

            writer.println("Path Type Distribution:");
            report.pathTypeCounts.forEach((type, count) -> writer.println("  " + type + ": " + count));
            writer.println();

            writer.println("Method Complexity Statistics:");
            report.methodComplexityStats.forEach((metric, value) -> writer.println("  " + metric + ": " + value));

        } catch (IOException e) {
            System.err.println("Error saving report: " + e.getMessage());
        }
    }

    /**
     * Cleanup resources
     */
    public void cleanup() {
        if (pathBuilder != null) {
            pathBuilder.cleanup();
        }
        if (constraintExtractor != null) {
            constraintExtractor.shutdown();
        }
    }

    // Utility methods
    private String sanitizeFileName(String fileName) {
        return fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private String escapeJson(String str) {
        return str.replace("\"", "\\\"").replace("\n", "\\n");
    }

    private String escapeCSV(String str) {
        if (str.contains(",") || str.contains("\"") || str.contains("\n")) {
            return "\"" + str.replace("\"", "\"\"") + "\"";
        }
        return str;
    }

    // Getters
    public AllocationGraphAnalyzer getGraphAnalyzer() {
        return graphAnalyzer;
    }

    public ConstraintExtractor getConstraintExtractor() {
        return constraintExtractor;
    }

    public ConstraintPathBuilder getPathBuilder() {
        return pathBuilder;
    }

    public AnalysisConfig getConfig() {
        return config;
    }

    public boolean isInitialized() {
        return initialized;
    }
}

/**
 * Configuration for backward constraint analysis
 */
class AnalysisConfig {
    private final LLMProvider llmProvider;
    private final String llmApiKey;
    private final String llmModel;
    private final String outputDirectory;
    private final boolean saveIntermediateResults;
    private final boolean enablePathMerging;
    private final int maxPathDepth;

    public AnalysisConfig(LLMProvider llmProvider, String llmApiKey, String llmModel, String outputDirectory) {
        this.llmProvider = llmProvider;
        this.llmApiKey = llmApiKey;
        this.llmModel = llmModel;
        this.outputDirectory = outputDirectory;
        this.saveIntermediateResults = false;
        this.enablePathMerging = true;
        this.maxPathDepth = 50;
    }

    // Getters
    public LLMProvider getLlmProvider() {
        return llmProvider;
    }

    public String getLlmApiKey() {
        return llmApiKey;
    }

    public String getLlmModel() {
        return llmModel;
    }

    public String getOutputDirectory() {
        return outputDirectory;
    }

    public boolean isSaveIntermediateResults() {
        return saveIntermediateResults;
    }

    public boolean isEnablePathMerging() {
        return enablePathMerging;
    }

    public int getMaxPathDepth() {
        return maxPathDepth;
    }
}

/**
 * Result of constraint analysis for a single method
 */
class ConstraintAnalysisResult {
    private final SootMethod targetMethod;
    private final List<ConstraintPath> paths;
    private final long analysisTimeMs;
    private final boolean successful;
    private final String errorMessage;

    public ConstraintAnalysisResult(SootMethod targetMethod, List<ConstraintPath> paths, long analysisTimeMs) {
        this.targetMethod = targetMethod;
        this.paths = paths;
        this.analysisTimeMs = analysisTimeMs;
        this.successful = true;
        this.errorMessage = null;
    }

    public ConstraintAnalysisResult(SootMethod targetMethod, List<ConstraintPath> paths,
            long analysisTimeMs, String errorMessage) {
        this.targetMethod = targetMethod;
        this.paths = paths;
        this.analysisTimeMs = analysisTimeMs;
        this.successful = false;
        this.errorMessage = errorMessage;
    }

    // Getters
    public SootMethod getTargetMethod() {
        return targetMethod;
    }

    public List<ConstraintPath> getPaths() {
        return Collections.unmodifiableList(paths);
    }

    public long getAnalysisTimeMs() {
        return analysisTimeMs;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}

/**
 * Overall analysis report
 */
class AnalysisReport {
    public int totalMethods;
    public int successfulAnalyses;
    public int totalPaths;
    public int totalValidPaths;
    public double averageAnalysisTime;
    public Map<ConstraintType, Integer> constraintTypeCounts;
    public Map<PathType, Integer> pathTypeCounts;
    public Map<String, Object> methodComplexityStats;
}