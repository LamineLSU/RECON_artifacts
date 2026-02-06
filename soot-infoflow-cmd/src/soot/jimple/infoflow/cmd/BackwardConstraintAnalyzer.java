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
 * Now supports three-format constraint output, app-agnostic analysis, and
 * comprehensive LLM interaction logging with detailed debug information.
 */
public class BackwardConstraintAnalyzer {
    private final AllocationGraphAnalyzer graphAnalyzer;
    private final ConstraintExtractor constraintExtractor;
    private final ConstraintPathBuilder pathBuilder;
    private final AnalysisConfig config;
    private final Map<SootMethod, List<ConstraintPath>> targetMethodToPaths;
    private final Set<SootMethod> analyzedTargets;
    private final LLMInteractionLogger interactionLogger;
    private boolean initialized;

    public BackwardConstraintAnalyzer(AllocationGraphAnalyzer graphAnalyzer, AnalysisConfig config) {
        this.graphAnalyzer = graphAnalyzer;
        this.config = config;
        this.targetMethodToPaths = new HashMap<>();
        this.analyzedTargets = new HashSet<>();
        this.initialized = false;

        // Initialize LLM interaction logger
        this.interactionLogger = new LLMInteractionLogger(config.getOutputDirectory());

        // Initialize constraint extractor with LLM configuration and logger
        LLMConfig llmConfig = new LLMConfig(
                config.getLlmProvider(),
                config.getLlmApiKey(),
                config.getLlmModel());
        this.constraintExtractor = new ConstraintExtractor(llmConfig, true, interactionLogger);

        // Initialize path builder with logger
        this.pathBuilder = new ConstraintPathBuilder(graphAnalyzer, constraintExtractor, interactionLogger);

        // Add session metadata
        interactionLogger.addSessionMetadata("analysis_config_provider", config.getLlmProvider().toString());
        interactionLogger.addSessionMetadata("analysis_config_model", config.getLlmModel());
        interactionLogger.addSessionMetadata("analysis_config_output_dir", config.getOutputDirectory());

        System.out.println("======================================================================");
        System.out.println("              BACKWARD CONSTRAINT ANALYZER INITIALIZED");
        System.out.println("                    WITH COMPREHENSIVE LOGGING");
        System.out.println("======================================================================");
        System.out.println("LLM Provider: " + config.getLlmProvider());
        System.out.println("LLM Model: " + config.getLlmModel());
        System.out.println("Output Directory: " + config.getOutputDirectory());
        System.out.println("LLM Logging: " + (interactionLogger.isEnabled() ? "ENABLED" : "DISABLED"));
    }

    /**
     * Initialize the analyzer (must be called before analysis)
     */
    public void initialize() {
        if (initialized) {
            return;
        }

        System.out.println("\n======================================================================");
        System.out.println("                    INITIALIZING ANALYZER");
        System.out.println("======================================================================");

        // Ensure allocation graph analyzer is initialized
        if (graphAnalyzer.getCallGraph() == null) {
            System.out.println("Initializing AllocationGraphAnalyzer...");
            graphAnalyzer.initializeAnalysis();
            graphAnalyzer.analyze();
            System.out.println("AllocationGraphAnalyzer initialized");
        }

        System.out.println("Analysis Statistics:");
        System.out.println("   Available methods: " + graphAnalyzer.getAnalyzedMethods().size());
        System.out.println("   Call graph edges: " + graphAnalyzer.getCallGraph().size());
        System.out.println("   Method graphs: " + graphAnalyzer.getMethodGraphs().size());

        // Add initialization metadata to logger
        interactionLogger.addSessionMetadata("total_methods",
                String.valueOf(graphAnalyzer.getAnalyzedMethods().size()));
        interactionLogger.addSessionMetadata("call_graph_edges", String.valueOf(graphAnalyzer.getCallGraph().size()));

        initialized = true;
        System.out.println("Analyzer initialization complete\n");
    }

    /**
     * Analyze constraints for a specific target method (app-agnostic) with
     * comprehensive logging
     */
    public ConstraintAnalysisResult analyzeMethod(SootMethod targetMethod) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized. Call initialize() first.");
        }

        System.out.println("\n======================================================================");
        System.out.println("                      ANALYZING TARGET METHOD");
        System.out.println("======================================================================");
        System.out.println("Target: " + targetMethod.getSignature());
        System.out.println("Started at: " + java.time.LocalDateTime.now());

        long startTime = System.currentTimeMillis();

        // Add method-specific metadata to logger
        interactionLogger.addSessionMetadata("current_target_method", targetMethod.getSignature());
        interactionLogger.addSessionMetadata("current_analysis_start", String.valueOf(startTime));

        try {
            System.out.println("\nBuilding constraint paths using step-by-step targeting...");

            // Build constraint paths to target method using step-by-step targeting
            List<ConstraintPath> paths = pathBuilder.buildPathsToTarget(targetMethod);

            long analysisTime = System.currentTimeMillis() - startTime;

            System.out.println("\nAnalysis Complete!");
            System.out.println("   Total time: " + analysisTime + "ms");
            System.out.println("   Paths found: " + paths.size());

            // Create analysis result
            ConstraintAnalysisResult result = new ConstraintAnalysisResult(
                    targetMethod, paths, analysisTime);

            // Cache result
            targetMethodToPaths.put(targetMethod, paths);
            analyzedTargets.add(targetMethod);

            // Add completion metadata to logger
            interactionLogger.addSessionMetadata("last_analysis_duration", String.valueOf(analysisTime));
            interactionLogger.addSessionMetadata("last_analysis_paths_found", String.valueOf(paths.size()));

            // Generate comprehensive summary with three-format support
            generateEnhancedAnalysisSummary(result);

            // Save LLM interactions for this analysis
            if (interactionLogger.isEnabled()) {
                System.out.println("\nSaving LLM interaction audit trail...");
                interactionLogger.saveToFiles();
                System.out.println("LLM audit trail saved to: " + config.getOutputDirectory());
            }

            return result;

        } catch (Exception e) {
            long analysisTime = System.currentTimeMillis() - startTime;
            System.err.println("ERROR: Error analyzing method " + targetMethod.getSignature() + ": " + e.getMessage());
            e.printStackTrace();

            // Log error to interaction logger
            interactionLogger.addSessionMetadata("last_analysis_error", e.getMessage());

            return new ConstraintAnalysisResult(
                    targetMethod, new ArrayList<>(), analysisTime,
                    "Analysis failed: " + e.getMessage());
        }
    }

    /**
     * Analyze constraints for multiple target methods with batch progress tracking
     */
    public Map<SootMethod, ConstraintAnalysisResult> analyzeMethods(Collection<SootMethod> targetMethods) {
        Map<SootMethod, ConstraintAnalysisResult> results = new HashMap<>();

        System.out.println("\n======================================================================");
        System.out.println("                      BATCH ANALYSIS MODE");
        System.out
                .println("                    " + String.format("%-3d", targetMethods.size()) + " METHODS TO ANALYZE");
        System.out.println("======================================================================");

        long batchStartTime = System.currentTimeMillis();
        int completed = 0;
        int failed = 0;

        for (SootMethod method : targetMethods) {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("BATCH PROGRESS: " + (++completed) + "/" + targetMethods.size() +
                    " (" + String.format("%.1f", (completed * 100.0 / targetMethods.size())) + "%)");
            System.out.println("=".repeat(80));

            ConstraintAnalysisResult result = analyzeMethod(method);
            results.put(method, result);

            if (!result.isSuccessful()) {
                failed++;
                System.out.println("Analysis failed for: " + method.getName());
            } else {
                System.out.println("Analysis completed for: " + method.getName() +
                        " (" + result.getPaths().size() + " paths)");
            }

            // Optional: save intermediate results
            if (config.isSaveIntermediateResults()) {
                saveResultToFile(result, config.getOutputDirectory());
            }

            // Memory management for large batches
            if (completed % 10 == 0) {
                System.gc(); // Suggest garbage collection every 10 methods
            }
        }

        long batchTime = System.currentTimeMillis() - batchStartTime;

        System.out.println("\n======================================================================");
        System.out.println("                    BATCH ANALYSIS COMPLETE");
        System.out.println("======================================================================");
        System.out.println("Batch Summary:");
        System.out.println("   Total methods: " + targetMethods.size());
        System.out.println("   Successful: " + (completed - failed));
        System.out.println("   Failed: " + failed);
        System.out.println("   Total time: " + batchTime + "ms");
        System.out.println("   Average per method: " + (batchTime / targetMethods.size()) + "ms");

        // Log batch statistics
        interactionLogger.addSessionMetadata("batch_total_methods", String.valueOf(targetMethods.size()));
        interactionLogger.addSessionMetadata("batch_successful", String.valueOf(completed - failed));
        interactionLogger.addSessionMetadata("batch_failed", String.valueOf(failed));
        interactionLogger.addSessionMetadata("batch_total_time", String.valueOf(batchTime));

        return results;
    }

    /**
     * Find target methods by name pattern (app-agnostic)
     */
    public List<SootMethod> findMethodsByName(String namePattern) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized");
        }

        System.out.println("Finding methods by name pattern: '" + namePattern + "'");

        List<SootMethod> matches = graphAnalyzer.getAnalyzedMethods().stream()
                .filter(method -> method.getName().contains(namePattern))
                .collect(Collectors.toList());

        System.out.println("   Found " + matches.size() + " matching methods");
        matches.forEach(method -> System.out.println("      • " + method.getSignature()));

        return matches;
    }

    /**
     * Find target methods in specific class (app-agnostic)
     */
    public List<SootMethod> findMethodsInClass(String className) {
        if (!initialized) {
            throw new IllegalStateException("Analyzer not initialized");
        }

        System.out.println("Finding methods in class: '" + className + "'");

        try {
            SootClass targetClass = Scene.v().getSootClass(className);
            List<SootMethod> matches = graphAnalyzer.getAnalyzedMethods().stream()
                    .filter(method -> method.getDeclaringClass().equals(targetClass))
                    .collect(Collectors.toList());

            System.out.println("   Found " + matches.size() + " methods in class");
            matches.forEach(method -> System.out.println("      • " + method.getName()));

            return matches;
        } catch (RuntimeException e) {
            System.err.println("ERROR: Class not found: " + className);
            return new ArrayList<>();
        }
    }

    /**
     * ENHANCED: Generate comprehensive analysis summary with three-format
     * constraint display and LLM statistics
     */
    private void generateEnhancedAnalysisSummary(ConstraintAnalysisResult result) {
        System.out.println("\n======================================================================");
        System.out.println("                    ENHANCED ANALYSIS SUMMARY");
        System.out.println("======================================================================");

        System.out.println("Target Method: " + result.getTargetMethod().getSignature());
        System.out.println("Analysis Time: " + result.getAnalysisTimeMs() + "ms");
        System.out.println("Total Paths Found: " + result.getPaths().size());

        long validPaths = result.getPaths().stream().filter(ConstraintPath::isValidPath).count();
        System.out.println("Valid Paths: " + validPaths);
        System.out.println("Invalid Paths: " + (result.getPaths().size() - validPaths));

        // LLM Interaction Statistics
        if (interactionLogger.isEnabled()) {
            System.out.println("\nLLM Interaction Statistics:");
            System.out.println("   Total LLM interactions: " + interactionLogger.getInteractionCount());
            System.out.println("   Session ID: " + interactionLogger.getSessionId());
        }

        if (!result.getPaths().isEmpty()) {
            // Show constraint statistics
            Map<ConstraintType, Long> constraintStats = result.getPaths().stream()
                    .flatMap(path -> path.getConstraints().stream())
                    .collect(Collectors.groupingBy(Constraint::getType, Collectors.counting()));

            System.out.println("\nConstraint Type Distribution:");
            constraintStats.forEach((type, count) -> System.out.println("   " + type + ": " + count));

            // ENHANCED: Show sample constraints in all three formats
            System.out.println("\nSample Constraints (Three Formats):");
            result.getPaths().stream()
                    .filter(ConstraintPath::isValidPath)
                    .limit(2)
                    .forEach(path -> {
                        System.out.println("   Path: " + path.getPathId());
                        if (!path.getConstraints().isEmpty()) {
                            Constraint sampleConstraint = path.getConstraints().get(0);
                            System.out.println("      Format 1 (Boolean Logic): " +
                                    truncateForDisplay(sampleConstraint.getFormat1(), 80));
                            System.out.println("      Format 2 (Business Context): " +
                                    truncateForDisplay(sampleConstraint.getFormat2(), 80));
                            System.out.println("      Format 3 (Technical Details): " +
                                    truncateForDisplay(sampleConstraint.getFormat3(), 80));
                        }
                    });

            // ENHANCED: Show combined logical expressions
            System.out.println("\nCombined Logical Expressions:");
            result.getPaths().stream()
                    .filter(ConstraintPath::isValidPath)
                    .limit(3)
                    .forEach(path -> {
                        String expression = path.getLogicalExpression();
                        System.out.println("   Path " + path.getPathId() + ":");
                        System.out.println("      " + truncateForDisplay(expression, 100));
                    });

            // Show sample path summaries with enhanced formatting
            System.out.println("\nSample Path Summaries (Business Context):");
            result.getPaths().stream()
                    .filter(ConstraintPath::isValidPath)
                    .limit(3)
                    .forEach(path -> {
                        String summary = path.getPathSummary(ConstraintFormat.FORMAT_2);
                        System.out.println("   " + summary);
                    });

            // Path complexity analysis
            System.out.println("\nPath Complexity Analysis:");
            double avgConstraints = result.getPaths().stream()
                    .mapToInt(ConstraintPath::getConstraintCount)
                    .average()
                    .orElse(0.0);
            int maxConstraints = result.getPaths().stream()
                    .mapToInt(ConstraintPath::getConstraintCount)
                    .max()
                    .orElse(0);
            double avgPathLength = result.getPaths().stream()
                    .mapToInt(ConstraintPath::getPathLength)
                    .average()
                    .orElse(0.0);

            System.out.println("   Average constraints per path: " + String.format("%.2f", avgConstraints));
            System.out.println("   Maximum constraints in a path: " + maxConstraints);
            System.out.println("   Average path length: " + String.format("%.2f", avgPathLength));
        }

        if (!result.isSuccessful()) {
            System.out.println("\nERROR: Analysis Error: " + result.getErrorMessage());
        }

        System.out.println("\n" + "=".repeat(80));
        System.out.println("Enhanced Analysis Summary Complete");
        System.out.println("=".repeat(80) + "\n");
    }

    /**
     * Generate comprehensive analysis report with three-format support and LLM
     * statistics
     */
    public AnalysisReport generateReport(Collection<ConstraintAnalysisResult> results) {
        System.out.println("\n======================================================================");
        System.out.println("                  GENERATING ANALYSIS REPORT");
        System.out.println("======================================================================");

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

        // LLM interaction statistics
        if (interactionLogger.isEnabled()) {
            Map<String, Object> llmStats = new HashMap<>();
            llmStats.put("total_interactions", interactionLogger.getInteractionCount());
            llmStats.put("session_id", interactionLogger.getSessionId());
            report.llmInteractionStats = llmStats;

            System.out.println("Report includes LLM interaction statistics");
        }

        System.out.println("Analysis report generated successfully");
        return report;
    }

    /**
     * Save analysis results to files with three-format support and LLM audit trails
     */
    public void saveResults(Collection<ConstraintAnalysisResult> results, String outputDirectory) {
        try {
            System.out.println("\nSaving analysis results with comprehensive audit trails...");

            Path outputPath = Paths.get(outputDirectory);
            Files.createDirectories(outputPath);

            // Save individual method results with all three formats
            System.out.println("   Saving individual method results...");
            for (ConstraintAnalysisResult result : results) {
                saveResultToFile(result, outputDirectory);
                saveResultWithFormats(result, outputDirectory);
            }

            // Save summary report
            System.out.println("   Generating and saving summary report...");
            AnalysisReport report = generateReport(results);
            saveReportToFile(report, outputPath.resolve("analysis_report.txt").toString());

            // Save constraint paths in different formats
            System.out.println("   Saving constraint paths in multiple formats...");
            savePathsAsJson(results, outputPath.resolve("constraint_paths.json").toString());
            savePathsAsCSV(results, outputPath.resolve("constraint_summary.csv").toString());

            // ENHANCED: Save paths with three-format constraints
            savePathsWithFormats(results, outputPath.resolve("constraint_paths_detailed.json").toString());

            // Save LLM interaction audit trail (if enabled)
            if (interactionLogger.isEnabled()) {
                System.out.println("   Saving LLM interaction audit trail...");
                interactionLogger.saveToFiles();
            }

            System.out.println("\nAll results saved successfully to: " + outputDirectory);
            System.out.println("Files generated:");
            System.out.println("   Individual method reports");
            System.out.println("   Detailed constraint formats");
            System.out.println("   Summary report (analysis_report.txt)");
            System.out.println("   JSON constraint paths");
            System.out.println("   CSV summary");
            System.out.println("   Detailed JSON with three formats");
            if (interactionLogger.isEnabled()) {
                System.out.println("   LLM interaction audit trail");
            }

        } catch (IOException e) {
            System.err.println("ERROR: Error saving results: " + e.getMessage());
        }
    }

    /**
     * ENHANCED: Save individual result with all three constraint formats
     */
    private void saveResultWithFormats(ConstraintAnalysisResult result, String outputDirectory) {
        try {
            Path outputPath = Paths.get(outputDirectory);
            Files.createDirectories(outputPath);

            String fileName = sanitizeFileName(result.getTargetMethod().getName()) + "_constraints_detailed.txt";
            Path filePath = outputPath.resolve(fileName);

            try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(filePath))) {
                writeResultWithFormatsToWriter(result, writer);
            }

        } catch (IOException e) {
            System.err.println("Error saving detailed result for method " +
                    result.getTargetMethod().getName() + ": " + e.getMessage());
        }
    }

    /**
     * ENHANCED: Write result with three-format constraints to writer
     */
    private void writeResultWithFormatsToWriter(ConstraintAnalysisResult result, PrintWriter writer) {
        writer.println("DETAILED CONSTRAINT ANALYSIS RESULT");
        writer.println("===================================");
        writer.println("Target Method: " + result.getTargetMethod().getSignature());
        writer.println("Analysis Time: " + result.getAnalysisTimeMs() + "ms");
        writer.println("Success: " + result.isSuccessful());
        writer.println("Generated: " + java.time.LocalDateTime.now());

        if (interactionLogger.isEnabled()) {
            writer.println("LLM Session ID: " + interactionLogger.getSessionId());
            writer.println("LLM Interactions: " + interactionLogger.getInteractionCount());
        }

        if (!result.isSuccessful()) {
            writer.println("Error: " + result.getErrorMessage());
            return;
        }

        writer.println("Total Paths: " + result.getPaths().size());
        writer.println();

        // Write each path with all three constraint formats
        for (int i = 0; i < result.getPaths().size(); i++) {
            ConstraintPath path = result.getPaths().get(i);
            writer.println("PATH " + (i + 1) + " (ID: " + path.getPathId() + ")");
            writer.println("=" + "=".repeat(50));
            writer.println("Valid: " + path.isValidPath());
            writer.println("Type: " + path.getPathType());

            if (!path.isValidPath()) {
                writer.println("Reason: " + path.getInvalidationReason());
            }

            writer.println();

            // Write constraints in all three formats
            if (!path.getConstraints().isEmpty()) {
                writer.println("CONSTRAINTS:");

                writer.println("  Format 1 (Boolean Logic):");
                List<String> format1 = path.getConstraintsFormat1();
                for (int j = 0; j < format1.size(); j++) {
                    writer.println("    " + (j + 1) + ". " + format1.get(j));
                }

                writer.println("  Format 2 (Business Context):");
                List<String> format2 = path.getConstraintsFormat2();
                for (int j = 0; j < format2.size(); j++) {
                    writer.println("    " + (j + 1) + ". " + format2.get(j));
                }

                writer.println("  Format 3 (Technical Details):");
                List<String> format3 = path.getConstraintsFormat3();
                for (int j = 0; j < format3.size(); j++) {
                    writer.println("    " + (j + 1) + ". " + format3.get(j));
                }

                writer.println("  Combined Logical Expression:");
                writer.println("    " + path.getLogicalExpression());
            }

            writer.println();
        }
    }

    /**
     * ENHANCED: Save paths with three-format constraints as detailed JSON
     */
    private void savePathsWithFormats(Collection<ConstraintAnalysisResult> results, String filePath) {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(filePath)))) {
            writer.println("{ \"detailed_constraint_analysis_results\": [");

            boolean first = true;
            for (ConstraintAnalysisResult result : results) {
                if (!first)
                    writer.println(",");
                writeDetailedResultAsJson(result, writer);
                first = false;
            }

            writer.println("\n]}");
        } catch (IOException e) {
            System.err.println("Error saving detailed JSON: " + e.getMessage());
        }
    }

    /**
     * ENHANCED: Write result as detailed JSON with three formats and LLM info
     */
    private void writeDetailedResultAsJson(ConstraintAnalysisResult result, PrintWriter writer) {
        writer.println("  {");
        writer.println("    \"method\": \"" + escapeJson(result.getTargetMethod().getSignature()) + "\",");
        writer.println("    \"analysis_time_ms\": " + result.getAnalysisTimeMs() + ",");
        writer.println("    \"successful\": " + result.isSuccessful() + ",");
        writer.println("    \"path_count\": " + result.getPaths().size() + ",");

        // Add LLM session info
        if (interactionLogger.isEnabled()) {
            writer.println("    \"llm_session_id\": \"" + interactionLogger.getSessionId() + "\",");
            writer.println("    \"llm_interactions\": " + interactionLogger.getInteractionCount() + ",");
        }

        writer.println("    \"paths\": [");

        for (int i = 0; i < result.getPaths().size(); i++) {
            ConstraintPath path = result.getPaths().get(i);
            if (i > 0)
                writer.println(",");

            writer.println("      {");
            writer.println("        \"id\": \"" + path.getPathId() + "\",");
            writer.println("        \"valid\": " + path.isValidPath() + ",");
            writer.println("        \"type\": \"" + path.getPathType() + "\",");
            writer.println("        \"constraint_count\": " + path.getConstraintCount() + ",");

            // Add all three constraint formats
            writer.println("        \"constraints_format1\": [");
            List<String> format1 = path.getConstraintsFormat1();
            for (int j = 0; j < format1.size(); j++) {
                if (j > 0)
                    writer.println(",");
                writer.print("          \"" + escapeJson(format1.get(j)) + "\"");
            }
            writer.println("\n        ],");

            writer.println("        \"constraints_format2\": [");
            List<String> format2 = path.getConstraintsFormat2();
            for (int j = 0; j < format2.size(); j++) {
                if (j > 0)
                    writer.println(",");
                writer.print("          \"" + escapeJson(format2.get(j)) + "\"");
            }
            writer.println("\n        ],");

            writer.println("        \"constraints_format3\": [");
            List<String> format3 = path.getConstraintsFormat3();
            for (int j = 0; j < format3.size(); j++) {
                if (j > 0)
                    writer.println(",");
                writer.print("          \"" + escapeJson(format3.get(j)) + "\"");
            }
            writer.println("\n        ],");

            writer.println("        \"logical_expression\": \"" + escapeJson(path.getLogicalExpression()) + "\"");
            writer.println("      }");
        }

        writer.println("    ]");
        writer.println("  }");
    }

    // Helper method for display truncation
    private String truncateForDisplay(String text, int maxLength) {
        if (text == null)
            return "null";
        if (text.length() <= maxLength)
            return text;
        return text.substring(0, maxLength) + "... (+" + (text.length() - maxLength) + " chars)";
    }

    /**
     * Cleanup resources including LLM interaction logger
     */
    public void cleanup() {
        if (pathBuilder != null) {
            pathBuilder.cleanup();
        }
        if (constraintExtractor != null) {
            constraintExtractor.shutdown();
        }
        if (interactionLogger != null) {
            System.out.println("Saving final LLM interaction logs...");
            interactionLogger.cleanup();
        }
        System.out.println("BackwardConstraintAnalyzer cleanup complete");
    }

    // ===== EXISTING METHODS (with enhanced error handling and logging) =====

    /**
     * Save individual result to file (existing functionality with enhanced logging)
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
     * Write result to writer (existing functionality)
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

        // Write each path with default format
        for (int i = 0; i < result.getPaths().size(); i++) {
            ConstraintPath path = result.getPaths().get(i);
            writer.println("Path " + (i + 1) + ":");
            writer.println(path.getPathDescription());
            writer.println();
        }
    }

    /**
     * Analyze method complexity (existing functionality)
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
     * Save paths as JSON (existing functionality)
     */
    private void savePathsAsJson(Collection<ConstraintAnalysisResult> results, String filePath) {
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
     * Write result as JSON (existing functionality)
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
     * Save paths as CSV summary (existing functionality)
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
     * Save report to file (existing functionality)
     */
    private void saveReportToFile(AnalysisReport report, String filePath) {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(Paths.get(filePath)))) {
            writer.println("Backward Constraint Analysis Report");
            writer.println("==================================");
            writer.println("Generated: " + java.time.LocalDateTime.now());
            writer.println();

            writer.println("Overall Statistics:");
            writer.println("  Total Methods Analyzed: " + report.totalMethods);
            writer.println("  Successful Analyses: " + report.successfulAnalyses);
            writer.println("  Total Paths Found: " + report.totalPaths);
            writer.println("  Valid Paths: " + report.totalValidPaths);
            writer.printf("  Average Analysis Time: %.2f ms%n", report.averageAnalysisTime);
            writer.println();

            // LLM interaction statistics
            if (report.llmInteractionStats != null) {
                writer.println("LLM Interaction Statistics:");
                report.llmInteractionStats.forEach((key, value) -> writer.println("  " + key + ": " + value));
                writer.println();
            }

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

    public Set<SootMethod> getAnalyzedTargets() {
        return Collections.unmodifiableSet(analyzedTargets);
    }

    public List<ConstraintPath> getPathsForMethod(SootMethod method) {
        return targetMethodToPaths.getOrDefault(method, new ArrayList<>());
    }

    public LLMInteractionLogger getInteractionLogger() {
        return interactionLogger;
    }
}

/**
 * Configuration for backward constraint analysis (existing with LLM info added)
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
 * Result of constraint analysis for a single method (existing)
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

    public List<SootMethod> getMethodSequence() {
        // Extract from constraint paths
        return getPaths().stream()
                .flatMap(path -> path.getMethodSequence().stream())
                .distinct()
                .collect(Collectors.toList());
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
 * Overall analysis report (existing with LLM stats added)
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
    public Map<String, Object> llmInteractionStats; // NEW: LLM interaction statistics
}