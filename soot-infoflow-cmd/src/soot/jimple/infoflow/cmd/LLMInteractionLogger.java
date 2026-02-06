package soot.jimple.infoflow.cmd;

import soot.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import com.google.gson.*;

/**
 * Comprehensive logger for LLM interactions during constraint analysis.
 * Captures prompts, responses, model info, and links to constraint paths.
 * Provides both JSON and human-readable audit trails with complete model
 * information.
 */
public class LLMInteractionLogger {
    private final String sessionId;
    private final String outputDirectory;
    private final List<LLMInteraction> interactions;
    private final Map<String, String> pathToInteractionMap;
    private final Map<String, String> sessionMetadata;
    private final DateTimeFormatter timestampFormatter;
    private final Gson gson;
    private boolean enabled;

    public LLMInteractionLogger(String outputDirectory) {
        this.sessionId = "session_" + System.currentTimeMillis();
        this.outputDirectory = outputDirectory;
        this.interactions = Collections.synchronizedList(new ArrayList<>());
        this.pathToInteractionMap = new ConcurrentHashMap<>();
        this.sessionMetadata = new ConcurrentHashMap<>();
        this.timestampFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.enabled = true;

        // Initialize session metadata
        initializeSessionMetadata();

        // Ensure output directory exists
        try {
            Files.createDirectories(Paths.get(outputDirectory));
        } catch (IOException e) {
            System.err.println("Warning: Could not create LLM log directory: " + e.getMessage());
            this.enabled = false;
        }
    }

    /**
     * Log an LLM interaction with full context and model information
     */
    public String logInteraction(String pathId, String targetMethod, String conditionStatement,
            String targetStatement, String prompt, LLMConfig config) {
        if (!enabled)
            return null;

        String interactionId = generateInteractionId();
        LLMInteraction interaction = new LLMInteraction(
                interactionId, pathId, targetMethod, conditionStatement, targetStatement, prompt, config);

        interactions.add(interaction);
        if (pathId != null) {
            pathToInteractionMap.put(pathId, interactionId);
        }

        // DEBUG: Stage 3 - LLM Interaction
        System.out.println("\n=== DEBUG: Stage 3 - LLM Interaction ===");
        System.out.println("DEBUG: Sending request to LLM");
        System.out.println("DEBUG: Interaction ID: " + interactionId);
        System.out.println("DEBUG: Path ID: " + pathId);
        System.out.println("DEBUG: Target Method: " + targetMethod);
        System.out.println("DEBUG: Model Provider: " + config.getProvider());
        System.out.println("DEBUG: Model Name: " + config.getModel());
        System.out.println("DEBUG: API Endpoint: " + config.getApiEndpoint());
        System.out.println("DEBUG: Max Tokens: " + config.getMaxTokens());
        System.out.println("DEBUG: Temperature: " + config.getTemperature());
        System.out.println("DEBUG: Prompt length: " + prompt.length() + " characters");
        System.out.println("DEBUG: Prompt preview: " + truncateString(prompt, 200));
        System.out.println("=========================================\n");

        return interactionId;
    }

    /**
     * Log LLM response for an interaction
     */
    public void logResponse(String interactionId, String response, boolean success,
            long responseTimeMs, String errorMessage) {
        if (!enabled || interactionId == null)
            return;

        LLMInteraction interaction = findInteractionById(interactionId);
        if (interaction != null) {
            interaction.setResponse(response, success, responseTimeMs, errorMessage);

            // DEBUG: Stage 3 - LLM Response
            System.out.println("\n=== DEBUG: Stage 3 - LLM Response ===");
            System.out.println("DEBUG: LLM response received: " + (success ? "success" : "failure"));
            System.out.println("DEBUG: Interaction ID: " + interactionId);
            System.out.println("DEBUG: Response success: " + success);
            System.out.println("DEBUG: Response time: " + responseTimeMs + "ms");
            System.out.println("DEBUG: Response length: " + (response != null ? response.length() : 0) + " characters");
            if (!success && errorMessage != null) {
                System.out.println("DEBUG: Error: " + errorMessage);
            }
            if (response != null) {
                System.out.println("DEBUG: Raw LLM response: " + truncateString(response, 500));
            }
            System.out.println("======================================\n");
        }
    }

    /**
     * Log constraint creation result
     */
    public void logConstraintCreation(String interactionId, String constraintId,
            String format1, String format2, String format3,
            boolean parseSuccess, String parseError) {
        if (!enabled || interactionId == null)
            return;

        LLMInteraction interaction = findInteractionById(interactionId);
        if (interaction != null) {
            interaction.setConstraintResult(constraintId, format1, format2, format3, parseSuccess, parseError);

            // DEBUG: Stage 5 - Constraint Creation
            System.out.println("\n=== DEBUG: Stage 5 - Constraint Creation ===");
            System.out.println("DEBUG: Creating constraint object");
            System.out.println("DEBUG: Interaction ID: " + interactionId);
            System.out.println("DEBUG: Constraint ID: " + constraintId);
            System.out.println("DEBUG: Parse success: " + parseSuccess);
            if (!parseSuccess && parseError != null) {
                System.out.println("DEBUG: Parse error: " + parseError);
            }
            if (parseSuccess) {
                System.out.println("DEBUG: Format1 (Boolean Logic): " + truncateString(format1, 150));
                System.out.println("DEBUG: Format2 (Business Context): " + truncateString(format2, 150));
                System.out.println("DEBUG: Format3 (Technical Details): " + truncateString(format3, 150));
            }
            System.out.println("==============================================\n");
        }
    }

    /**
     * Log path assembly information
     */
    public void logPathAssembly(String pathId, int totalConstraints, boolean pathValid, String invalidReason) {
        if (!enabled)
            return;

        // DEBUG: Stage 6 - Path Assembly
        System.out.println("\n=== DEBUG: Stage 6 - Path Assembly ===");
        System.out.println("DEBUG: Added constraint to path: " + pathId);
        System.out.println("DEBUG: Total constraints in path: " + totalConstraints);
        System.out.println("DEBUG: Path validation: " + (pathValid ? "valid" : "invalid"));
        if (!pathValid && invalidReason != null) {
            System.out.println("DEBUG: Invalid reason: " + invalidReason);
        }

        String interactionId = pathToInteractionMap.get(pathId);
        if (interactionId != null) {
            System.out.println("DEBUG: Linked LLM interaction: " + interactionId);
        }
        System.out.println("=====================================\n");
    }

    /**
     * Add session metadata
     */
    public void addSessionMetadata(String key, String value) {
        sessionMetadata.put(key, value);
    }

    /**
     * Save all interactions to files
     */
    public void saveToFiles() {
        if (!enabled || interactions.isEmpty())
            return;

        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

            // Save JSON format
            saveAsJson(timestamp);

            // Save human-readable format
            saveAsText(timestamp);

            // Save summary
            saveSummary(timestamp);

            System.out.println("\n=== LLM Interaction Logs Saved ===");
            System.out.println("Session ID: " + sessionId);
            System.out.println("Total interactions: " + interactions.size());
            System.out.println("Files saved to: " + outputDirectory);
            System.out.println("===================================\n");

        } catch (IOException e) {
            System.err.println("Error saving LLM interaction logs: " + e.getMessage());
        }
    }

    /**
     * Save interactions as JSON with comprehensive model information
     */
    private void saveAsJson(String timestamp) throws IOException {
        String fileName = "llm_interactions_" + timestamp + ".json";
        Path filePath = Paths.get(outputDirectory, fileName);

        Map<String, Object> data = new HashMap<>();
        data.put("session_id", sessionId);
        data.put("timestamp", LocalDateTime.now().format(timestampFormatter));
        data.put("total_interactions", interactions.size());

        // Add session metadata
        data.put("session_metadata", new HashMap<>(sessionMetadata));

        // Add interactions with full model information
        List<Map<String, Object>> interactionList = new ArrayList<>();
        for (LLMInteraction interaction : interactions) {
            Map<String, Object> interactionData = new HashMap<>();

            // Basic interaction info
            interactionData.put("interaction_id", interaction.interactionId);
            interactionData.put("path_id", interaction.pathId);
            interactionData.put("timestamp", interaction.timestamp);
            interactionData.put("target_method", interaction.targetMethod);

            // Context information
            interactionData.put("condition_statement", interaction.conditionStatement);
            interactionData.put("target_statement", interaction.targetStatement);

            // Prompt and response
            interactionData.put("prompt", interaction.prompt);
            interactionData.put("prompt_length", interaction.prompt.length());
            interactionData.put("response", interaction.response);
            interactionData.put("response_length", interaction.response != null ? interaction.response.length() : 0);
            interactionData.put("response_success", interaction.responseSuccess);
            interactionData.put("response_time_ms", interaction.responseTimeMs);
            interactionData.put("error_message", interaction.errorMessage);

            // Complete model information
            Map<String, Object> modelInfo = new HashMap<>();
            modelInfo.put("provider", interaction.modelProvider);
            modelInfo.put("model_name", interaction.modelName);
            modelInfo.put("api_endpoint", interaction.apiEndpoint);
            modelInfo.put("max_tokens", interaction.maxTokens);
            modelInfo.put("temperature", interaction.temperature);
            interactionData.put("model_info", modelInfo);

            // Constraint result information
            if (interaction.constraintId != null) {
                Map<String, Object> constraintInfo = new HashMap<>();
                constraintInfo.put("constraint_id", interaction.constraintId);
                constraintInfo.put("parse_success", interaction.parseSuccess);
                constraintInfo.put("parse_error", interaction.parseError);
                constraintInfo.put("format1", interaction.format1);
                constraintInfo.put("format2", interaction.format2);
                constraintInfo.put("format3", interaction.format3);
                interactionData.put("constraint_result", constraintInfo);
            }

            interactionList.add(interactionData);
        }

        data.put("interactions", interactionList);

        try (FileWriter writer = new FileWriter(filePath.toFile())) {
            gson.toJson(data, writer);
        }
    }

    /**
     * Save interactions as human-readable text with complete model details
     */
    private void saveAsText(String timestamp) throws IOException {
        String fileName = "llm_interactions_" + timestamp + ".txt";
        Path filePath = Paths.get(outputDirectory, fileName);

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(filePath))) {
            writer.println("LLM INTERACTION AUDIT TRAIL");
            writer.println("===========================");
            writer.println("Session ID: " + sessionId);
            writer.println("Generated: " + LocalDateTime.now().format(timestampFormatter));
            writer.println("Total Interactions: " + interactions.size());
            writer.println();

            // Session metadata
            writer.println("SESSION METADATA:");
            sessionMetadata.forEach((key, value) -> writer.println("  " + key + ": " + value));
            writer.println();

            // Individual interactions with detailed model information
            for (int i = 0; i < interactions.size(); i++) {
                LLMInteraction interaction = interactions.get(i);
                writer.println("INTERACTION " + (i + 1) + "/" + interactions.size());
                writer.println("=" + "=".repeat(60));
                writeInteractionToText(interaction, writer);
                writer.println();
            }
        }
    }

    /**
     * Save summary statistics with model usage analysis
     */
    private void saveSummary(String timestamp) throws IOException {
        String fileName = "llm_analysis_summary_" + timestamp + ".txt";
        Path filePath = Paths.get(outputDirectory, fileName);

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(filePath))) {
            writer.println("LLM Analysis Summary");
            writer.println("===================");
            writer.println("Session ID: " + sessionId);
            writer.println("Generated: " + LocalDateTime.now().format(timestampFormatter));
            writer.println();

            // Statistics
            long successfulInteractions = interactions.stream().filter(i -> i.responseSuccess).count();
            long failedInteractions = interactions.size() - successfulInteractions;
            OptionalDouble avgResponseTime = interactions.stream()
                    .filter(i -> i.responseTimeMs > 0)
                    .mapToLong(i -> i.responseTimeMs)
                    .average();

            writer.println("Statistics:");
            writer.println("  Total interactions: " + interactions.size());
            writer.println("  Successful: " + successfulInteractions);
            writer.println("  Failed: " + failedInteractions);
            writer.printf("  Average response time: %.2f ms%n", avgResponseTime.orElse(0.0));
            writer.println();

            // Model usage analysis
            Map<String, Long> modelUsage = new HashMap<>();
            Map<String, Long> providerUsage = new HashMap<>();
            Map<String, Long> endpointUsage = new HashMap<>();

            for (LLMInteraction interaction : interactions) {
                String model = interaction.modelProvider + "/" + interaction.modelName;
                modelUsage.merge(model, 1L, Long::sum);
                providerUsage.merge(interaction.modelProvider, 1L, Long::sum);
                endpointUsage.merge(interaction.apiEndpoint, 1L, Long::sum);
            }

            writer.println("Model Usage:");
            modelUsage.forEach((model, count) -> writer.println("  " + model + ": " + count + " interactions"));
            writer.println();

            writer.println("Provider Usage:");
            providerUsage
                    .forEach((provider, count) -> writer.println("  " + provider + ": " + count + " interactions"));
            writer.println();

            writer.println("API Endpoint Usage:");
            endpointUsage
                    .forEach((endpoint, count) -> writer.println("  " + endpoint + ": " + count + " interactions"));
            writer.println();

            // Model configuration analysis
            writer.println("Model Configuration Analysis:");
            Set<Double> temperatures = new HashSet<>();
            Set<Integer> maxTokens = new HashSet<>();
            for (LLMInteraction interaction : interactions) {
                temperatures.add(interaction.temperature);
                maxTokens.add(interaction.maxTokens);
            }
            writer.println("  Temperature values used: " + temperatures);
            writer.println("  Max tokens values used: " + maxTokens);
            writer.println();

            // Error analysis
            if (failedInteractions > 0) {
                writer.println("Errors:");
                interactions.stream()
                        .filter(i -> !i.responseSuccess && i.errorMessage != null)
                        .forEach(i -> writer.println("  " + i.interactionId + ": " + i.errorMessage));
                writer.println();
            }

            // Constraint parsing success rate
            long constraintParseSuccess = interactions.stream()
                    .filter(i -> i.constraintId != null && i.parseSuccess)
                    .count();
            long constraintParseFailure = interactions.stream()
                    .filter(i -> i.constraintId != null && !i.parseSuccess)
                    .count();

            if (constraintParseSuccess + constraintParseFailure > 0) {
                writer.println("Constraint Parsing:");
                writer.println("  Successful: " + constraintParseSuccess);
                writer.println("  Failed: " + constraintParseFailure);
                writer.printf("  Success rate: %.2f%%%n",
                        (constraintParseSuccess * 100.0) / (constraintParseSuccess + constraintParseFailure));
            }
        }
    }

    /**
     * Write single interaction to text format with complete model information
     */
    private void writeInteractionToText(LLMInteraction interaction, PrintWriter writer) {
        writer.println("ID: " + interaction.interactionId);
        writer.println("Path ID: " + interaction.pathId);
        writer.println("Timestamp: " + interaction.timestamp);
        writer.println("Target Method: " + interaction.targetMethod);
        writer.println();

        // Complete model information
        writer.println("Model Information:");
        writer.println("  Provider: " + interaction.modelProvider);
        writer.println("  Model: " + interaction.modelName);
        writer.println("  API Endpoint: " + interaction.apiEndpoint);
        writer.println("  Max Tokens: " + interaction.maxTokens);
        writer.println("  Temperature: " + interaction.temperature);
        writer.println();

        writer.println("Context:");
        writer.println("  Condition: " + interaction.conditionStatement);
        writer.println("  Target: " + interaction.targetStatement);
        writer.println();

        writer.println("Prompt (" + interaction.prompt.length() + " chars):");
        writer.println(indentText(interaction.prompt, "  "));
        writer.println();

        if (interaction.response != null) {
            writer.println("Response (" + interaction.response.length() + " chars, "
                    + interaction.responseTimeMs + "ms, success: " + interaction.responseSuccess + "):");
            writer.println(indentText(interaction.response, "  "));
            writer.println();
        }

        if (interaction.errorMessage != null) {
            writer.println("Error:");
            writer.println("  " + interaction.errorMessage);
            writer.println();
        }

        if (interaction.constraintId != null) {
            writer.println("Generated Constraint:");
            writer.println("  ID: " + interaction.constraintId);
            writer.println("  Parse Success: " + interaction.parseSuccess);
            if (interaction.parseSuccess) {
                writer.println("  Format1 (Boolean Logic): " + interaction.format1);
                writer.println("  Format2 (Business Context): " + interaction.format2);
                writer.println("  Format3 (Technical Details): " + interaction.format3);
            } else if (interaction.parseError != null) {
                writer.println("  Parse Error: " + interaction.parseError);
            }
        }
    }

    /**
     * Initialize session metadata with system information
     */
    private void initializeSessionMetadata() {
        sessionMetadata.put("session_start", LocalDateTime.now().format(timestampFormatter));
        sessionMetadata.put("java_version", System.getProperty("java.version"));
        sessionMetadata.put("os_name", System.getProperty("os.name"));
        sessionMetadata.put("os_version", System.getProperty("os.version"));
        sessionMetadata.put("user_dir", System.getProperty("user.dir"));
        sessionMetadata.put("max_memory", String.valueOf(Runtime.getRuntime().maxMemory()));
        sessionMetadata.put("available_processors", String.valueOf(Runtime.getRuntime().availableProcessors()));
    }

    // Utility methods
    private String generateInteractionId() {
        return sessionId + "_interaction_" + (interactions.size() + 1);
    }

    private LLMInteraction findInteractionById(String interactionId) {
        return interactions.stream()
                .filter(i -> i.interactionId.equals(interactionId))
                .findFirst()
                .orElse(null);
    }

    private String truncateString(String str, int maxLength) {
        if (str == null)
            return "null";
        if (str.length() <= maxLength)
            return str;
        return str.substring(0, maxLength) + "... [truncated, total: " + str.length() + " chars]";
    }

    private String indentText(String text, String indent) {
        if (text == null)
            return indent + "null";
        return indent + text.replace("\n", "\n" + indent);
    }

    /**
     * Get interaction record by ID
     */
    public LLMInteraction getInteractionById(String interactionId) {
        return findInteractionById(interactionId);
    }

    /**
     * Get all interactions for a constraint path
     */
    public List<LLMInteraction> getInteractionsForPath(String pathId) {
        return interactions.stream()
                .filter(i -> pathId.equals(i.pathId))
                .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Cleanup resources and save final logs
     */
    public void cleanup() {
        saveToFiles();
        System.out.println("LLMInteractionLogger cleanup complete - all logs saved");
    }

    // Getters
    public String getSessionId() {
        return sessionId;
    }

    public int getInteractionCount() {
        return interactions.size();
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Disable logging (for testing or performance)
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Get all interactions (for analysis)
     */
    public List<LLMInteraction> getAllInteractions() {
        return new ArrayList<>(interactions);
    }

    /**
     * Inner class representing a single LLM interaction with complete model
     * information
     */
    public static class LLMInteraction {
        final String interactionId;
        final String pathId;
        final String targetMethod;
        final String conditionStatement;
        final String targetStatement;
        final String prompt;
        final String timestamp;

        // Complete model information
        final String modelProvider;
        final String modelName;
        final String apiEndpoint;
        final int maxTokens;
        final double temperature;

        // Response data
        String response;
        boolean responseSuccess;
        long responseTimeMs;
        String errorMessage;

        // Constraint result with three formats
        String constraintId;
        String format1;
        String format2;
        String format3;
        boolean parseSuccess;
        String parseError;

        LLMInteraction(String interactionId, String pathId, String targetMethod,
                String conditionStatement, String targetStatement,
                String prompt, LLMConfig config) {
            this.interactionId = interactionId;
            this.pathId = pathId;
            this.targetMethod = targetMethod;
            this.conditionStatement = conditionStatement;
            this.targetStatement = targetStatement;
            this.prompt = prompt;
            this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));

            // Store complete model configuration
            this.modelProvider = config.getProvider().toString();
            this.modelName = config.getModel();
            this.apiEndpoint = config.getApiEndpoint();
            this.maxTokens = config.getMaxTokens();
            this.temperature = config.getTemperature();
        }

        void setResponse(String response, boolean success, long responseTimeMs, String errorMessage) {
            this.response = response;
            this.responseSuccess = success;
            this.responseTimeMs = responseTimeMs;
            this.errorMessage = errorMessage;
        }

        void setConstraintResult(String constraintId, String format1, String format2, String format3,
                boolean parseSuccess, String parseError) {
            this.constraintId = constraintId;
            this.format1 = format1;
            this.format2 = format2;
            this.format3 = format3;
            this.parseSuccess = parseSuccess;
            this.parseError = parseError;
        }

        // Getters for external access
        public String getInteractionId() {
            return interactionId;
        }

        public String getPathId() {
            return pathId;
        }

        public String getTargetMethod() {
            return targetMethod;
        }

        public String getConditionStatement() {
            return conditionStatement;
        }

        public String getTargetStatement() {
            return targetStatement;
        }

        public String getPrompt() {
            return prompt;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public String getModelProvider() {
            return modelProvider;
        }

        public String getModelName() {
            return modelName;
        }

        public String getApiEndpoint() {
            return apiEndpoint;
        }

        public int getMaxTokens() {
            return maxTokens;
        }

        public double getTemperature() {
            return temperature;
        }

        public String getResponse() {
            return response;
        }

        public boolean isResponseSuccess() {
            return responseSuccess;
        }

        public long getResponseTimeMs() {
            return responseTimeMs;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public String getConstraintId() {
            return constraintId;
        }

        public String getFormat1() {
            return format1;
        }

        public String getFormat2() {
            return format2;
        }

        public String getFormat3() {
            return format3;
        }

        public boolean isParseSuccess() {
            return parseSuccess;
        }

        public String getParseError() {
            return parseError;
        }
    }
}