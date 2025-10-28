package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import com.google.gson.*;

/**
 * Handles extraction of human-readable constraints from Jimple IR using LLM
 * analysis.
 * Converts Soot variables and conditions into meaningful constraint
 * descriptions.
 */
public class ConstraintExtractor {
    private final LLMService llmService;
    private final Map<String, String> variableCache;
    private final Map<String, String> constraintCache;
    private final ExecutorService executorService;
    private final int maxRetries;
    private final boolean useLLM; // NEW: Flag to enable/disable LLM

    public ConstraintExtractor(LLMConfig config) {
        this(config, true); // Default: use LLM
    }

    public ConstraintExtractor(LLMConfig config, boolean useLLM) {
        this.useLLM = useLLM;
        this.variableCache = new ConcurrentHashMap<>();
        this.constraintCache = new ConcurrentHashMap<>();
        this.maxRetries = config != null ? config.getMaxRetries() : 3;

        if (useLLM && config != null) {
            this.llmService = new LLMService(config);
            this.executorService = Executors.newFixedThreadPool(config.getMaxConcurrentRequests());
        } else {
            this.llmService = null;
            this.executorService = null;
            System.out.println("ConstraintExtractor: Running in NO-LLM mode - using fallback methods");
        }
    }

    /**
     * Extract constraint from an IF_CONDITION node
     */
    public ConditionalConstraint extractConditionalConstraint(AllocationNode ifNode, boolean takeTrueBranch) {
        if (ifNode.getType() != NodeType.IF_CONDITION) {
            throw new IllegalArgumentException("Node must be IF_CONDITION type");
        }

        Unit ifUnit = ifNode.getUnit();
        SootMethod method = ifNode.getMethod();

        if (!(ifUnit instanceof IfStmt)) {
            throw new IllegalArgumentException("Unit must be IfStmt for IF_CONDITION node");
        }

        IfStmt ifStmt = (IfStmt) ifUnit;
        Value condition = ifStmt.getCondition();

        // Generate unique ID for this constraint
        String constraintId = generateConstraintId(method, ifUnit, "conditional");

        String humanReadable;
        if (useLLM) {
            // Check cache first
            String cacheKey = method.getSignature() + ":" + condition.toString() + ":" + takeTrueBranch;
            humanReadable = constraintCache.get(cacheKey);

            if (humanReadable == null) {
                // Extract using LLM
                humanReadable = extractConditionWithLLM(method, condition, takeTrueBranch);
                constraintCache.put(cacheKey, humanReadable);
            }
        } else {
            // Use fallback method
            humanReadable = generateFallbackCondition(condition, takeTrueBranch);
        }

        // Parse condition components
        ConditionComponents components = parseCondition(condition, humanReadable);

        return new ConditionalConstraint(
                constraintId, method, ifUnit, humanReadable, takeTrueBranch,
                components.variable, components.operator, components.value);
    }

    /**
     * Extract constraint from a SWITCH node
     */
    public SwitchConstraint extractSwitchConstraint(AllocationNode switchNode, String caseValue, boolean isDefault) {
        if (switchNode.getType() != NodeType.SWITCH) {
            throw new IllegalArgumentException("Node must be SWITCH type");
        }

        Unit switchUnit = switchNode.getUnit();
        SootMethod method = switchNode.getMethod();

        // Generate unique ID for this constraint
        String constraintId = generateConstraintId(method, switchUnit, "switch");

        String humanReadable;
        if (useLLM) {
            // Check cache first
            String cacheKey = method.getSignature() + ":" + switchUnit.toString() + ":" + caseValue;
            humanReadable = constraintCache.get(cacheKey);

            if (humanReadable == null) {
                // Extract using LLM
                humanReadable = extractSwitchWithLLM(method, switchUnit, caseValue, isDefault);
                constraintCache.put(cacheKey, humanReadable);
            }
        } else {
            // Use fallback method
            humanReadable = generateFallbackSwitch(switchUnit, caseValue, isDefault);
        }

        // Extract switch variable
        String switchVariable = extractSwitchVariable(switchUnit, humanReadable);

        return new SwitchConstraint(
                constraintId, method, switchUnit, humanReadable,
                switchVariable, caseValue, isDefault);
    }

    /**
     * Extract constraints from method call parameters
     */
    public List<ParameterConstraint> extractParameterConstraints(AllocationNode callNode, SootMethod targetMethod) {
        if (callNode.getType() != NodeType.METHOD_CALL) {
            throw new IllegalArgumentException("Node must be METHOD_CALL type");
        }

        InvokeExpr invoke = callNode.getMethodCall();
        if (invoke == null || !invoke.getMethod().equals(targetMethod)) {
            return new ArrayList<>();
        }

        List<ParameterConstraint> constraints = new ArrayList<>();
        SootMethod sourceMethod = callNode.getMethod();
        Unit callUnit = callNode.getUnit();

        // Analyze each parameter
        List<Value> args = invoke.getArgs();
        for (int i = 0; i < args.size(); i++) {
            Value arg = args.get(i);

            String parameterInfo;
            if (useLLM) {
                // Check if this parameter has constraints
                parameterInfo = analyzeParameterWithLLM(sourceMethod, callUnit, arg, i);
            } else {
                // Use simple fallback
                parameterInfo = generateFallbackParameterInfo(arg, i);
            }

            if (parameterInfo != null && !parameterInfo.trim().isEmpty()) {
                String constraintId = generateConstraintId(sourceMethod, callUnit, "param_" + i);

                constraints.add(new ParameterConstraint(
                        constraintId, sourceMethod, callUnit, parameterInfo,
                        i, "param_" + i, parameterInfo, arg.getType().toString()));
            }
        }

        return constraints;
    }

    /**
     * Extract variable name using LLM analysis or fallback
     */
    public String extractVariableName(SootMethod method, Value variable) {
        if (useLLM) {
            String cacheKey = method.getSignature() + ":" + variable.toString();
            String cachedResult = variableCache.get(cacheKey);

            if (cachedResult != null) {
                return cachedResult;
            }

            String humanName = extractVariableWithLLM(method, variable);
            variableCache.put(cacheKey, humanName);
            return humanName;
        } else {
            return generateFallbackVariableName(variable);
        }
    }

    /**
     * Extract condition using LLM
     */
    private String extractConditionWithLLM(SootMethod method, Value condition, boolean takeTrueBranch) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String prompt = buildConditionPrompt(methodBody, condition, takeTrueBranch);

            LLMRequest request = new LLMRequest(prompt, LLMRequestType.CONDITION_EXTRACTION);
            LLMResponse response = llmService.sendRequest(request);

            return cleanLLMResponse(response.getContent());

        } catch (Exception e) {
            System.err.println("Error extracting condition with LLM: " + e.getMessage());
            return generateFallbackCondition(condition, takeTrueBranch);
        }
    }

    /**
     * Extract switch constraint using LLM
     */
    private String extractSwitchWithLLM(SootMethod method, Unit switchUnit, String caseValue, boolean isDefault) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String prompt = buildSwitchPrompt(methodBody, switchUnit, caseValue, isDefault);

            LLMRequest request = new LLMRequest(prompt, LLMRequestType.SWITCH_EXTRACTION);
            LLMResponse response = llmService.sendRequest(request);

            return cleanLLMResponse(response.getContent());

        } catch (Exception e) {
            System.err.println("Error extracting switch with LLM: " + e.getMessage());
            return generateFallbackSwitch(switchUnit, caseValue, isDefault);
        }
    }

    /**
     * Extract variable name using LLM
     */
    private String extractVariableWithLLM(SootMethod method, Value variable) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String prompt = buildVariablePrompt(methodBody, variable);

            LLMRequest request = new LLMRequest(prompt, LLMRequestType.VARIABLE_NAMING);
            LLMResponse response = llmService.sendRequest(request);

            return cleanLLMResponse(response.getContent());

        } catch (Exception e) {
            System.err.println("Error extracting variable with LLM: " + e.getMessage());
            return generateFallbackVariableName(variable);
        }
    }

    /**
     * Analyze method parameter using LLM
     */
    private String analyzeParameterWithLLM(SootMethod method, Unit callUnit, Value parameter, int index) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String prompt = buildParameterPrompt(methodBody, callUnit, parameter, index);

            LLMRequest request = new LLMRequest(prompt, LLMRequestType.PARAMETER_ANALYSIS);
            LLMResponse response = llmService.sendRequest(request);

            return cleanLLMResponse(response.getContent());

        } catch (Exception e) {
            System.err.println("Error analyzing parameter with LLM: " + e.getMessage());
            return null;
        }
    }

    /**
     * Build prompt for condition extraction
     */
    private String buildConditionPrompt(String methodBody, Value condition, boolean takeTrueBranch) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this Android/Java method and convert the Jimple condition to human-readable form:\n\n");
        prompt.append("Method Body (Jimple IR):\n");
        prompt.append(methodBody).append("\n\n");
        prompt.append("Target Condition: ").append(condition.toString()).append("\n");
        prompt.append("Branch Taken: ").append(takeTrueBranch ? "TRUE" : "FALSE").append("\n\n");
        prompt.append("Please provide a human-readable description of what this condition means ");
        prompt.append("in the context of the method. Focus on:\n");
        prompt.append("1. What variables represent (user input, settings, state, etc.)\n");
        prompt.append("2. The semantic meaning of the condition\n");
        prompt.append("3. Use meaningful names instead of Jimple variables ($i0, $r1, etc.)\n\n");
        prompt.append("Example output: 'user.age > 18' or 'settings.isEnabled == true'\n");
        prompt.append("Response (only the condition, no explanation):");

        return prompt.toString();
    }

    /**
     * Build prompt for switch extraction
     */
    private String buildSwitchPrompt(String methodBody, Unit switchUnit, String caseValue, boolean isDefault) {
        StringBuilder prompt = new StringBuilder();
        prompt.append(
                "Analyze this Android/Java method and convert the Jimple switch statement to human-readable form:\n\n");
        prompt.append("Method Body (Jimple IR):\n");
        prompt.append(methodBody).append("\n\n");
        prompt.append("Switch Statement: ").append(switchUnit.toString()).append("\n");

        if (isDefault) {
            prompt.append("Case: DEFAULT\n\n");
        } else {
            prompt.append("Case Value: ").append(caseValue).append("\n\n");
        }

        prompt.append("Please provide a human-readable description of this switch condition ");
        prompt.append("in the context of the method. Focus on:\n");
        prompt.append("1. What the switch variable represents\n");
        prompt.append("2. The semantic meaning of the case value\n");
        prompt.append("3. Use meaningful names instead of Jimple variables\n\n");
        prompt.append("Example output: 'userType == ADMIN' or 'requestCode == LOGIN_REQUEST'\n");
        prompt.append("Response (only the condition, no explanation):");

        return prompt.toString();
    }

    /**
     * Build prompt for variable naming
     */
    private String buildVariablePrompt(String methodBody, Value variable) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this Android/Java method and determine what this Jimple variable represents:\n\n");
        prompt.append("Method Body (Jimple IR):\n");
        prompt.append(methodBody).append("\n\n");
        prompt.append("Target Variable: ").append(variable.toString()).append("\n\n");
        prompt.append("Please provide a meaningful name for this variable based on:\n");
        prompt.append("1. How it's used in the method\n");
        prompt.append("2. What values are assigned to it\n");
        prompt.append("3. Android/Java naming conventions\n");
        prompt.append("4. The business logic context\n\n");
        prompt.append("Example outputs: 'user_age', 'is_premium_user', 'login_attempts', 'view_button'\n");
        prompt.append("Response (only the variable name, no explanation):");

        return prompt.toString();
    }

    /**
     * Build prompt for parameter analysis
     */
    private String buildParameterPrompt(String methodBody, Unit callUnit, Value parameter, int index) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this Android/Java method call parameter:\n\n");
        prompt.append("Method Body (Jimple IR):\n");
        prompt.append(methodBody).append("\n\n");
        prompt.append("Method Call: ").append(callUnit.toString()).append("\n");
        prompt.append("Parameter ").append(index).append(": ").append(parameter.toString()).append("\n\n");
        prompt.append("If this parameter has constraints or meaningful values, describe them.\n");
        prompt.append("Return empty if the parameter is unconstrained.\n\n");
        prompt.append("Examples:\n");
        prompt.append("- 'userId must be > 0'\n");
        prompt.append("- 'permission must be CAMERA'\n");
        prompt.append("- '' (empty for unconstrained)\n\n");
        prompt.append("Response:");

        return prompt.toString();
    }

    /**
     * Get method body as Jimple string
     */
    private String getMethodBodyAsString(SootMethod method) {
        if (!method.hasActiveBody()) {
            return "Method has no active body";
        }

        StringBuilder sb = new StringBuilder();
        Body body = method.getActiveBody();

        sb.append("Method: ").append(method.getSignature()).append("\n");
        sb.append("Parameters: ");
        for (int i = 0; i < method.getParameterCount(); i++) {
            sb.append("param").append(i).append(":").append(method.getParameterType(i)).append(" ");
        }
        sb.append("\n\n");

        // Add method body units
        for (Unit unit : body.getUnits()) {
            sb.append(unit.toString()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Parse condition components from LLM response
     */
    private ConditionComponents parseCondition(Value originalCondition, String humanReadable) {
        // Try to extract components from human readable description
        Pattern pattern = Pattern.compile("([\\w.]+)\\s*(==|!=|>|<|>=|<=)\\s*(\\w+)");
        Matcher matcher = pattern.matcher(humanReadable);

        if (matcher.find()) {
            return new ConditionComponents(matcher.group(1), matcher.group(2), matcher.group(3));
        }

        // Fallback to parsing original condition
        String condStr = originalCondition.toString();
        if (condStr.contains(" gt ")) {
            String[] parts = condStr.split(" gt ");
            return new ConditionComponents(parts[0].trim(), ">", parts[1].trim());
        }
        // Add more condition parsing logic...

        return new ConditionComponents("unknown", "unknown", "unknown");
    }

    /**
     * Extract switch variable from unit
     */
    private String extractSwitchVariable(Unit switchUnit, String humanReadable) {
        // Try to extract from human readable first
        Pattern pattern = Pattern.compile("([\\w.]+)\\s*==");
        Matcher matcher = pattern.matcher(humanReadable);

        if (matcher.find()) {
            return matcher.group(1);
        }

        // Fallback to parsing unit
        return "switch_var";
    }

    /**
     * Generate unique constraint ID
     */
    private String generateConstraintId(SootMethod method, Unit unit, String type) {
        return method.getSignature().hashCode() + "_" + unit.hashCode() + "_" + type;
    }

    /**
     * Clean LLM response
     */
    private String cleanLLMResponse(String response) {
        if (response == null)
            return "";

        // Remove common LLM artifacts
        response = response.trim();
        response = response.replaceAll("^Response:\\s*", "");
        response = response.replaceAll("^Answer:\\s*", "");
        response = response.replaceAll("^Output:\\s*", "");

        return response;
    }

    /**
     * Generate fallback condition when LLM fails or disabled
     */
    private String generateFallbackCondition(Value condition, boolean takeTrueBranch) {
        String base = condition.toString()
                .replace("$", "var_") // Make variables more readable
                .replace(" gt ", " > ")
                .replace(" lt ", " < ")
                .replace(" ge ", " >= ")
                .replace(" le ", " <= ")
                .replace(" eq ", " == ")
                .replace(" ne ", " != ");

        return takeTrueBranch ? "[" + base + "]" : "[!(" + base + ")]";
    }

    /**
     * Generate fallback switch description
     */
    private String generateFallbackSwitch(Unit switchUnit, String caseValue, boolean isDefault) {
        if (isDefault) {
            return "[switch_var == default]";
        }
        return "[switch_var == " + caseValue + "]";
    }

    /**
     * Generate fallback variable name
     */
    private String generateFallbackVariableName(Value variable) {
        String type = variable.getType().toString();
        String varStr = variable.toString().replace("$", "var_");

        if (type.contains("boolean"))
            return varStr + "_bool";
        if (type.contains("int"))
            return varStr + "_int";
        if (type.contains("String"))
            return varStr + "_string";
        return varStr;
    }

    /**
     * Generate fallback parameter info
     */
    private String generateFallbackParameterInfo(Value parameter, int index) {
        // Only return info for non-simple parameters
        String paramStr = parameter.toString();
        if (paramStr.startsWith("$") && paramStr.matches("\\$[ir]\\d+")) {
            return null; // Skip simple variables
        }

        return "param[" + index + "] = " + paramStr.replace("$", "var_");
    }

    /**
     * Cleanup resources
     */
    public void shutdown() {
        if (executorService != null) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
            }
        }
    }

    // Inner classes
    private static class ConditionComponents {
        final String variable;
        final String operator;
        final String value;

        ConditionComponents(String variable, String operator, String value) {
            this.variable = variable;
            this.operator = operator;
            this.value = value;
        }
    }
}

/**
 * LLM Service for handling API requests
 */
class LLMService {
    private final HttpClient httpClient;
    private final LLMConfig config;
    private final Gson gson;

    public LLMService(LLMConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.gson = new Gson();
    }

    public LLMResponse sendRequest(LLMRequest request) throws Exception {
        // Build HTTP request based on LLM provider
        HttpRequest httpRequest = buildHttpRequest(request);

        // Send request
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("LLM request failed with status: " + response.statusCode());
        }

        // Parse response based on LLM provider
        return parseResponse(response.body());
    }

    private HttpRequest buildHttpRequest(LLMRequest request) {
        JsonObject requestBody = new JsonObject();

        if (config.getProvider() == LLMProvider.OPENAI ||
                config.getProvider() == LLMProvider.GROQ ||
                config.getProvider() == LLMProvider.OLLAMA) {
            JsonArray messages = new JsonArray();
            JsonObject message = new JsonObject();
            message.addProperty("role", "user");
            message.addProperty("content", request.getPrompt());
            messages.add(message);

            requestBody.addProperty("model", config.getModel());
            requestBody.add("messages", messages);
            requestBody.addProperty("max_tokens", config.getMaxTokens());
            requestBody.addProperty("temperature", config.getTemperature());
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.getApiEndpoint()))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(requestBody)));

        // Add authorization for API providers (not for local OLLAMA)
        if (config.getProvider() == LLMProvider.OPENAI || config.getProvider() == LLMProvider.GROQ) {
            builder.header("Authorization", "Bearer " + config.getApiKey());
        }

        return builder.build();
    }

    private LLMResponse parseResponse(String responseBody) {
        JsonObject jsonResponse = gson.fromJson(responseBody, JsonObject.class);

        if (config.getProvider() == LLMProvider.OPENAI ||
                config.getProvider() == LLMProvider.GROQ ||
                config.getProvider() == LLMProvider.OLLAMA) {
            JsonArray choices = jsonResponse.getAsJsonArray("choices");
            if (choices.size() > 0) {
                JsonObject choice = choices.get(0).getAsJsonObject();
                JsonObject message = choice.getAsJsonObject("message");
                String content = message.get("content").getAsString();
                return new LLMResponse(content, true);
            }
        }

        return new LLMResponse("", false);
    }
}

/**
 * Configuration for LLM service
 */
class LLMConfig {
    private final LLMProvider provider;
    private final String apiKey;
    private final String apiEndpoint;
    private final String model;
    private final int maxTokens;
    private final double temperature;
    private final int maxConcurrentRequests;
    private final int maxRetries;

    public LLMConfig(LLMProvider provider, String apiKey, String model) {
        this.provider = provider;
        this.apiKey = apiKey;
        this.model = model;
        this.maxTokens = 150;
        this.temperature = 0.1;
        this.maxConcurrentRequests = 5;
        this.maxRetries = 3;

        // Set default endpoints
        switch (provider) {
            case OPENAI:
                this.apiEndpoint = "https://api.openai.com/v1/chat/completions";
                break;
            case ANTHROPIC:
                this.apiEndpoint = "https://api.anthropic.com/v1/messages";
                break;
            case GROQ:
                this.apiEndpoint = "https://api.groq.com/openai/v1/chat/completions";
                break;
            case OLLAMA:
                this.apiEndpoint = "http://localhost:11434/v1/chat/completions";
                break;
            default:
                this.apiEndpoint = "";
        }
    }

    // Getters
    public LLMProvider getProvider() {
        return provider;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getApiEndpoint() {
        return apiEndpoint;
    }

    public String getModel() {
        return model;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public double getTemperature() {
        return temperature;
    }

    public int getMaxConcurrentRequests() {
        return maxConcurrentRequests;
    }

    public int getMaxRetries() {
        return maxRetries;
    }
}

/**
 * LLM request wrapper
 */
class LLMRequest {
    private final String prompt;
    private final LLMRequestType type;

    public LLMRequest(String prompt, LLMRequestType type) {
        this.prompt = prompt;
        this.type = type;
    }

    public String getPrompt() {
        return prompt;
    }

    public LLMRequestType getType() {
        return type;
    }
}

/**
 * LLM response wrapper
 */
class LLMResponse {
    private final String content;
    private final boolean success;

    public LLMResponse(String content, boolean success) {
        this.content = content;
        this.success = success;
    }

    public String getContent() {
        return content;
    }

    public boolean isSuccess() {
        return success;
    }
}

/**
 * Enumeration of LLM providers
 */
enum LLMProvider {
    OPENAI,
    ANTHROPIC,
    GROQ,
    OLLAMA,
    LOCAL
}

/**
 * Enumeration of LLM request types
 */
enum LLMRequestType {
    CONDITION_EXTRACTION,
    SWITCH_EXTRACTION,
    VARIABLE_NAMING,
    PARAMETER_ANALYSIS
}