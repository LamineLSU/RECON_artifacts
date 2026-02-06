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
 * Now uses step-by-step targeting approach with comprehensive prompts
 * and full audit trail logging.
 */
public class ConstraintExtractor {
    private final LLMService llmService;
    private final Map<String, String> variableCache;
    private final Map<String, String> constraintCache;
    private final ExecutorService executorService;
    private final int maxRetries;
    private final boolean useLLM;
    private final LLMInteractionLogger interactionLogger;

    public ConstraintExtractor(LLMConfig config) {
        this(config, true, null);
    }

    public ConstraintExtractor(LLMConfig config, boolean useLLM) {
        this(config, useLLM, null);
    }

    public ConstraintExtractor(LLMConfig config, boolean useLLM, LLMInteractionLogger logger) {
        this.useLLM = useLLM;
        this.variableCache = new ConcurrentHashMap<>();
        this.constraintCache = new ConcurrentHashMap<>();
        this.maxRetries = config != null ? config.getMaxRetries() : 3;
        this.interactionLogger = logger;

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
     * Extract constraint for single condition with immediate target
     * (step-by-step approach with enhanced logging)
     */
    public Constraint extractSingleConditionConstraint(AllocationNode conditionNode, AllocationNode targetNode,
            SootMethod method) {
        if (conditionNode.getType() != NodeType.IF_CONDITION) {
            return null;
        }

        Unit ifUnit = conditionNode.getUnit();
        if (!(ifUnit instanceof IfStmt)) {
            return null;
        }

        IfStmt ifStmt = (IfStmt) ifUnit;
        Value condition = ifStmt.getCondition();

        // DEBUG: Stage 1 - Condition Discovery
        System.out.println("\n=== DEBUG: Stage 1 - Condition Discovery ===");
        System.out.println("DEBUG: Found condition node: " + conditionNode.getId());
        System.out.println("DEBUG: Condition statement: " + ifStmt.toString());
        System.out.println("DEBUG: Target statement: " + getTargetStatementString(targetNode));
        System.out.println("DEBUG: Method context: " + method.getName());
        System.out.println("=============================================\n");

        // Generate unique ID for this constraint
        String constraintId = generateConstraintId(method, ifUnit, "conditional");

        String humanReadable;
        String format1 = "";
        String format2 = "";
        String format3 = "";

        if (useLLM) {
            // Build comprehensive prompt with step-by-step targeting
            SingleConditionResult result = extractSingleConditionWithLLM(conditionNode, targetNode, method);
            if (result != null) {
                humanReadable = result.format1; // Use format1 as primary
                format1 = result.format1;
                format2 = result.format2;
                format3 = result.format3;
            } else {
                // Fallback
                humanReadable = generateFallbackCondition(condition, true);
                format1 = humanReadable;
                format2 = humanReadable;
                format3 = humanReadable;
            }
        } else {
            // Use fallback method
            humanReadable = generateFallbackCondition(condition, true);
            format1 = humanReadable;
            format2 = humanReadable;
            format3 = humanReadable;
        }

        // Parse condition components
        ConditionComponents components = parseCondition(condition, humanReadable);

        // DEBUG: Stage 5 - Constraint Creation
        System.out.println("\n--- DEBUG: Stage 5 - Constraint Creation ---");
        System.out.println("DEBUG: Creating constraint object");
        System.out.println("DEBUG: Constraint ID: " + constraintId);
        System.out.println("DEBUG: Format1: " + format1);
        System.out.println("DEBUG: Format2: " + format2);
        System.out.println("DEBUG: Format3: " + format3);
        System.out.println("--------------------------------------------\n");

        // Create enhanced conditional constraint with three formats
        return new EnhancedConditionalConstraint(
                constraintId, method, ifUnit, humanReadable, true,
                components.variable, components.operator, components.value,
                format1, format2, format3);
    }

    /**
     * Extract single condition using comprehensive LLM prompt with step-by-step
     * targeting and full logging
     */
    private SingleConditionResult extractSingleConditionWithLLM(AllocationNode conditionNode, AllocationNode targetNode,
            SootMethod method) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String conditionStatement = conditionNode.getUnit().toString();
            String targetStatement = getTargetStatementString(targetNode);

            // DEBUG: Stage 2 - Prompt Construction
            System.out.println("\n=== DEBUG: Stage 2 - Prompt Construction ===");
            System.out.println("DEBUG: Building LLM prompt");
            System.out.println("DEBUG: Method body length: " + methodBody.length() + " characters");
            System.out.println("DEBUG: Condition: " + conditionStatement);
            System.out.println("DEBUG: Target: " + targetStatement);

            String prompt = buildComprehensivePrompt(methodBody, conditionStatement, targetStatement);

            System.out.println("DEBUG: Prompt length: " + prompt.length() + " characters");
            System.out.println("DEBUG: Prompt preview: " + truncateForDisplay(prompt, 200));
            System.out.println("==============================================\n");

            // Log interaction start
            String interactionId = null;
            if (interactionLogger != null && interactionLogger.isEnabled()) {
                interactionId = interactionLogger.logInteraction(
                        "path_" + System.nanoTime(), // Will be updated with real path ID later
                        method.getSignature(),
                        conditionStatement,
                        targetStatement,
                        prompt,
                        llmService.getConfig());
            }

            // Send LLM request
            LLMRequest request = new LLMRequest(prompt, LLMRequestType.SINGLE_CONDITION_EXTRACTION);

            long startTime = System.currentTimeMillis();
            LLMResponse response = llmService.sendRequest(request);
            long responseTime = System.currentTimeMillis() - startTime;

            // Log response
            if (interactionLogger != null && interactionId != null) {
                interactionLogger.logResponse(
                        interactionId,
                        response.getContent(),
                        response.isSuccess(),
                        responseTime,
                        response.isSuccess() ? null : "LLM request failed");
            }

            if (!response.isSuccess()) {
                System.err.println("LLM request failed for condition: " + conditionStatement);
                return null;
            }

            // DEBUG: Stage 4 - Response Parsing
            System.out.println("\n--- DEBUG: Stage 4 - Response Parsing ---");
            System.out.println("DEBUG: Parsing LLM response");
            System.out.println("DEBUG: Response length: " + response.getContent().length() + " characters");
            System.out.println("DEBUG: Raw LLM response: " + response.getContent());

            SingleConditionResult result = parseStructuredLLMResponse(response.getContent());

            boolean parseSuccess = result != null;
            String parseError = null;

            if (parseSuccess) {
                System.out.println("DEBUG: Extracted branch direction: " + result.branchDirection);
                System.out.println("DEBUG: Extracted variables: [parsed from response]");
                System.out.println("DEBUG: Extracted constraint: " + result.format2);
            } else {
                parseError = "Failed to parse LLM response structure";
                System.out.println("DEBUG: Parse error: " + parseError);
            }

            System.out.println("DEBUG: Parsing success: " + parseSuccess);
            System.out.println("------------------------------------------\n");

            // Log constraint creation
            if (interactionLogger != null && interactionId != null) {
                interactionLogger.logConstraintCreation(
                        interactionId,
                        result != null ? generateConstraintId(method, conditionNode.getUnit(), "conditional") : null,
                        result != null ? result.format1 : null,
                        result != null ? result.format2 : null,
                        result != null ? result.format3 : null,
                        parseSuccess,
                        parseError);
            }

            return result;

        } catch (Exception e) {
            System.err.println("Error extracting single condition with LLM: " + e.getMessage());
            return null;
        }
    }

    /**
     * Build comprehensive prompt with full analysis + placeholders for clean
     * extraction
     */
    private String buildComprehensivePrompt(String methodBody, String conditionStatement, String targetStatement) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("Given the bytecode for the method below:\n");
        prompt.append("[METHOD_BODY]\n");
        prompt.append(methodBody).append("\n");

        prompt.append("And this conditional statement in the method: \"").append(conditionStatement).append("\"\n");
        prompt.append(
                "Analyze this condition to determine the execution constraint needed to reach the target statement: \"")
                .append(targetStatement).append("\"\n");

        prompt.append("INSTRUCTIONS:\n");
        prompt.append("1. Identify ALL variables used in the conditional statement\n");
        prompt.append(
                "2. For each variable, trace its definition by finding the LAST assignment before this condition\n");
        prompt.append("3. Be mindful of variable reassignment - use the most recent assignment to each variable\n");
        prompt.append("4. If any variable is assigned the return value of a framework method, explain:\n");
        prompt.append("   - What the framework method does\n");
        prompt.append("   - What type it returns (boolean, int, String, etc.)\n");
        prompt.append("   - What the possible return values are\n");
        prompt.append("   - What each return value signifies in the business/application context\n");
        prompt.append("5. Determine which branch (TRUE or FALSE) of this condition leads to the target statement\n");
        prompt.append("6. Provide the constraint in human-readable form using meaningful terms, not variable names\n");
        prompt.append(
                "7. IMPORTANT: Replace bytecode variable names (z0, i1, etc.) with meaningful names based on what they represent (intent, menuItem, userInput, etc.) by analyzing their assignments\n");

        prompt.append("ANALYSIS REQUIREMENTS:\n");
        prompt.append(
                "- Trace execution flow from the condition through labels/gotos to determine the correct branch\n");
        prompt.append(
                "- For framework method calls like Intent.hasExtra(), MenuItem.getItemId(), etc., explain their semantic meaning\n");
        prompt.append("- Convert technical conditions into business logic constraints\n");
        prompt.append("- Focus only on this specific conditional statement\n");

        prompt.append("OUTPUT FORMAT:\n");
        prompt.append("Branch Direction: [TRUE/FALSE - which branch leads to target]\n\n");

        prompt.append("Variables:\n");
        prompt.append("[For each variable in condition]\n");
        prompt.append("Variable: [variable name]\n");
        prompt.append("Assignment: [last assignment statement]\n");
        prompt.append("Framework Method: [if applicable, name and purpose]\n");
        prompt.append("Return Type: [data type]\n");
        prompt.append("Possible Values: [range/options of return values]\n");
        prompt.append("Meaning: [what this represents in application context]\n\n");

        prompt.append("Constraint (Human Readable): [Business logic constraint in plain English]\n\n");

        prompt.append("Now analyze the given condition and target.\n\n");

        prompt.append("After your complete analysis above, provide clean outputs in these markers:\n\n");

        prompt.append("BRANCH_DIRECTION_START\n");
        prompt.append("[TRUE or FALSE only]\n");
        prompt.append("BRANCH_DIRECTION_END\n\n");

        prompt.append("BOOLEAN_CONSTRAINT_START\n");
        prompt.append("[Clean boolean expression only using meaningful variable names]\n");
        prompt.append("BOOLEAN_CONSTRAINT_END\n\n");

        prompt.append("BUSINESS_CONSTRAINT_START\n");
        prompt.append("[Single sentence requirement only]\n");
        prompt.append("BUSINESS_CONSTRAINT_END\n\n");

        prompt.append("TECHNICAL_CONSTRAINT_START\n");
        prompt.append("[Framework method info only]\n");
        prompt.append("TECHNICAL_CONSTRAINT_END");

        return prompt.toString();
    }

    /**
     * Parse structured LLM response using placeholder markers
     */
    private SingleConditionResult parseStructuredLLMResponse(String response) {
        if (response == null || response.trim().isEmpty()) {
            return null;
        }

        SingleConditionResult result = new SingleConditionResult();

        try {
            // Parse branch direction using placeholder markers
            String branchDirection = extractBetweenMarkers(response, "BRANCH_DIRECTION_START", "BRANCH_DIRECTION_END");
            if (branchDirection != null) {
                result.branchDirection = branchDirection.trim().equalsIgnoreCase("TRUE");
            }

            // Parse Format 1 (Boolean Logic) using placeholder markers
            result.format1 = extractBetweenMarkers(response, "BOOLEAN_CONSTRAINT_START", "BOOLEAN_CONSTRAINT_END");
            if (result.format1 != null) {
                result.format1 = result.format1.trim();
            }

            // Parse Format 2 (Business Logic) using placeholder markers
            result.format2 = extractBetweenMarkers(response, "BUSINESS_CONSTRAINT_START", "BUSINESS_CONSTRAINT_END");
            if (result.format2 != null) {
                result.format2 = result.format2.trim();
            }

            // Parse Format 3 (Technical Context) using placeholder markers
            result.format3 = extractBetweenMarkers(response, "TECHNICAL_CONSTRAINT_START", "TECHNICAL_CONSTRAINT_END");
            if (result.format3 != null) {
                result.format3 = result.format3.trim();
            }

            // Fallback handling - ensure all formats have values
            if (result.format1 == null || result.format1.isEmpty()) {
                result.format1 = result.format2 != null ? result.format2 : "unknown_condition";
            }
            if (result.format2 == null || result.format2.isEmpty()) {
                result.format2 = result.format1 != null ? result.format1 : "Condition must be met";
            }
            if (result.format3 == null || result.format3.isEmpty()) {
                result.format3 = result.format1 != null ? result.format1 : "Technical condition analysis";
            }

        } catch (Exception e) {
            System.err.println("Error parsing structured LLM response: " + e.getMessage());
            return null;
        }

        return result;
    }

    /**
     * Extract content between start and end markers
     */
    private String extractBetweenMarkers(String text, String startMarker, String endMarker) {
        if (text == null || startMarker == null || endMarker == null) {
            return null;
        }

        int startIndex = text.indexOf(startMarker);
        if (startIndex == -1) {
            return null;
        }

        startIndex += startMarker.length();
        int endIndex = text.indexOf(endMarker, startIndex);
        if (endIndex == -1) {
            return null;
        }

        String extracted = text.substring(startIndex, endIndex);
        return extracted.trim();
    }

    /**
     * Extract framework method information from variables section
     */
    private String extractFrameworkMethodInfo(String variablesSection) {
        StringBuilder techInfo = new StringBuilder();

        // Look for framework method patterns
        Pattern frameworkPattern = Pattern.compile("Framework Method:\\s*(.+?)(?=\\n|$)", Pattern.CASE_INSENSITIVE);
        Matcher frameworkMatcher = frameworkPattern.matcher(variablesSection);

        if (frameworkMatcher.find()) {
            techInfo.append("Framework method: ").append(frameworkMatcher.group(1).trim());
        }

        // Look for return type information
        Pattern returnTypePattern = Pattern.compile("Return Type:\\s*(.+?)(?=\\n|$)", Pattern.CASE_INSENSITIVE);
        Matcher returnTypeMatcher = returnTypePattern.matcher(variablesSection);

        if (returnTypeMatcher.find()) {
            if (techInfo.length() > 0)
                techInfo.append("; ");
            techInfo.append("Returns: ").append(returnTypeMatcher.group(1).trim());
        }

        return techInfo.length() > 0 ? techInfo.toString() : "Technical condition analysis";
    }

    /**
     * Generate boolean logic format from variables section
     */
    private String generateBooleanLogicFormat(String variablesSection, String businessContext) {
        // Try to extract variable names and create boolean expression
        Pattern variablePattern = Pattern.compile("Variable:\\s*(.+?)(?=\\n|$)", Pattern.CASE_INSENSITIVE);
        Matcher variableMatcher = variablePattern.matcher(variablesSection);

        List<String> variables = new ArrayList<>();
        while (variableMatcher.find()) {
            variables.add(variableMatcher.group(1).trim());
        }

        if (!variables.isEmpty()) {
            // Simple boolean logic format
            return variables.get(0) + " == condition_value";
        }

        // Fallback to business context if no variables found
        return businessContext != null ? businessContext : "condition_check";
    }

    /**
     * Get target statement string for prompt
     */
    private String getTargetStatementString(AllocationNode targetNode) {
        if (targetNode.getUnit() != null) {
            return targetNode.getUnit().toString();
        } else if (targetNode.getType() == NodeType.METHOD_CALL && targetNode.getMethodCall() != null) {
            return targetNode.getMethodCall().toString();
        } else {
            return "target_statement";
        }
    }

    /**
     * Legacy method for backward compatibility - extract constraint from
     * IF_CONDITION node
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
                // Extract using LLM (legacy method)
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
     * Legacy: Extract condition using LLM
     */
    private String extractConditionWithLLM(SootMethod method, Value condition, boolean takeTrueBranch) {
        try {
            String methodBody = getMethodBodyAsString(method);
            String prompt = buildLegacyConditionPrompt(methodBody, condition, takeTrueBranch);

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
     * Legacy: Build prompt for condition extraction (simpler version)
     */
    private String buildLegacyConditionPrompt(String methodBody, Value condition, boolean takeTrueBranch) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Convert this Jimple condition to readable form:\n\n");
        prompt.append("Method context (first 500 chars):\n");
        prompt.append(methodBody.substring(0, Math.min(500, methodBody.length()))).append("...\n\n");
        prompt.append("Condition: ").append(condition.toString()).append("\n");
        prompt.append("Branch taken: ").append(takeTrueBranch ? "TRUE" : "FALSE").append("\n\n");
        prompt.append("Return only the readable condition:");

        return prompt.toString();
    }

    /**
     * Build prompt for switch extraction
     */
    private String buildSwitchPrompt(String methodBody, Unit switchUnit, String caseValue, boolean isDefault) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Convert this Jimple switch to readable form:\n\n");
        prompt.append("Method context (first 500 chars):\n");
        prompt.append(methodBody.substring(0, Math.min(500, methodBody.length()))).append("...\n\n");
        prompt.append("Switch Statement: ").append(switchUnit.toString()).append("\n");

        if (isDefault) {
            prompt.append("Case: DEFAULT\n\n");
        } else {
            prompt.append("Case Value: ").append(caseValue).append("\n\n");
        }

        prompt.append("Return only the readable condition:");

        return prompt.toString();
    }

    /**
     * Build prompt for variable naming
     */
    private String buildVariablePrompt(String methodBody, Value variable) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Determine what this variable represents:\n\n");
        prompt.append("Method context (first 500 chars):\n");
        prompt.append(methodBody.substring(0, Math.min(500, methodBody.length()))).append("...\n\n");
        prompt.append("Variable: ").append(variable.toString()).append("\n\n");
        prompt.append("Return only the variable meaning:");

        return prompt.toString();
    }

    /**
     * Build prompt for parameter analysis
     */
    private String buildParameterPrompt(String methodBody, Unit callUnit, Value parameter, int index) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this method parameter:\n\n");
        prompt.append("Method context (first 500 chars):\n");
        prompt.append(methodBody.substring(0, Math.min(500, methodBody.length()))).append("...\n\n");
        prompt.append("Method Call: ").append(callUnit.toString()).append("\n");
        prompt.append("Parameter ").append(index).append(": ").append(parameter.toString()).append("\n\n");
        prompt.append("Return constraint if any:");

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
        if (condStr.contains(" eq ")) {
            String[] parts = condStr.split(" eq ");
            return new ConditionComponents(parts[0].trim(), "==", parts[1].trim());
        }
        if (condStr.contains(" ne ")) {
            String[] parts = condStr.split(" ne ");
            return new ConditionComponents(parts[0].trim(), "!=", parts[1].trim());
        }

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

        response = response.trim();

        // Remove common prefixes
        response = response.replaceAll("^(Response|Answer|Output|Condition|The condition is):?\\s*", "");
        response = response.replaceAll("^Format \\d[^:]*:\\s*", "");

        // Extract first meaningful line
        String[] lines = response.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("This") && !line.startsWith("In this")) {
                response = line;
                break;
            }
        }

        // Remove quotes and brackets
        response = response.replaceAll("^[\"\\[]+|[\"\\]]+$", "");

        // Remove explanatory text
        response = response.replaceAll("\\s*\\(.*?\\)\\s*", "");

        return response.trim();
    }

    /**
     * Truncate text for display
     */
    private String truncateForDisplay(String text, int maxLength) {
        if (text == null)
            return "null";
        if (text.length() <= maxLength)
            return text;
        return text.substring(0, maxLength) + "... [+" + (text.length() - maxLength) + " chars]";
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

    /**
     * Result container for single condition LLM analysis
     */
    private static class SingleConditionResult {
        boolean branchDirection;
        String format1; // Boolean logic
        String format2; // Business context
        String format3; // Technical details
    }
}

/**
 * Enhanced conditional constraint with three output formats
 */
class EnhancedConditionalConstraint extends ConditionalConstraint {
    private final String format1; // Boolean logic
    private final String format2; // Business context
    private final String format3; // Technical details

    public EnhancedConditionalConstraint(String constraintId, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, boolean requiredValue,
            String variable, String operator, String value,
            String format1, String format2, String format3) {
        super(constraintId, sourceMethod, sourceUnit, humanReadableCondition, requiredValue, variable, operator, value);
        this.format1 = format1;
        this.format2 = format2;
        this.format3 = format3;
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

        // add delay before making request (rate-limiting)
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Build HTTP request based on LLM provider
        HttpRequest httpRequest = buildHttpRequest(request);

        // Send request
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 429) {
            System.out.println("Rate limited 429, waiting for 5 seconds and retrying...");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // Retry the request once
            response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        }

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

    // Getter for config access
    public LLMConfig getConfig() {
        return config;
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
        this.maxTokens = 1000; // Increased for comprehensive prompts
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
    PARAMETER_ANALYSIS,
    SINGLE_CONDITION_EXTRACTION
}