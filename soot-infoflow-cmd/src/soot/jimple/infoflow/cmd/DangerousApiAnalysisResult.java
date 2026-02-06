package soot.jimple.infoflow.cmd;

import com.google.gson.annotations.SerializedName;
import java.util.*;

/**
 * Analysis results for a single dangerous API method, including call chains
 * leading to the API and constraints that must be satisfied.
 */
public class DangerousApiAnalysisResult {

    @SerializedName("method_signature")
    private String methodSignature;

    @SerializedName("api_category")
    private String apiCategory;

    @SerializedName("severity_level")
    private String severityLevel;

    @SerializedName("analysis_status")
    private AnalysisStatus analysisStatus;

    @SerializedName("analysis_error_message")
    private String analysisErrorMessage;

    @SerializedName("call_chains")
    private List<MethodCallChain> callChains;

    @SerializedName("constraints_found")
    private List<ConstraintSpecification> constraintsFound;

    @SerializedName("analysis_metrics")
    private AnalysisMetrics analysisMetrics;

    // Constructors
    public DangerousApiAnalysisResult(String methodSignature, String apiCategory, String severityLevel) {
        this.methodSignature = methodSignature;
        this.apiCategory = apiCategory;
        this.severityLevel = severityLevel;
        this.analysisStatus = AnalysisStatus.PENDING;
        this.callChains = new ArrayList<>();
        this.constraintsFound = new ArrayList<>();
        this.analysisMetrics = new AnalysisMetrics();
    }

    // Add call chain
    public void addCallChain(MethodCallChain callChain) {
        this.callChains.add(callChain);
    }

    // Add constraint
    public void addConstraint(ConstraintSpecification constraint) {
        this.constraintsFound.add(constraint);
    }

    // Mark analysis as completed
    public void setAnalysisCompleted(boolean success, String errorMessage) {
        this.analysisStatus = success ? AnalysisStatus.SUCCESS : AnalysisStatus.FAILED;
        this.analysisErrorMessage = errorMessage;
        this.analysisMetrics.setAnalysisCompleted();
    }

    // Getters and Setters
    public String getMethodSignature() {
        return methodSignature;
    }

    public void setMethodSignature(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public String getApiCategory() {
        return apiCategory;
    }

    public void setApiCategory(String apiCategory) {
        this.apiCategory = apiCategory;
    }

    public String getSeverityLevel() {
        return severityLevel;
    }

    public void setSeverityLevel(String severityLevel) {
        this.severityLevel = severityLevel;
    }

    public AnalysisStatus getAnalysisStatus() {
        return analysisStatus;
    }

    public void setAnalysisStatus(AnalysisStatus analysisStatus) {
        this.analysisStatus = analysisStatus;
    }

    public String getAnalysisErrorMessage() {
        return analysisErrorMessage;
    }

    public void setAnalysisErrorMessage(String analysisErrorMessage) {
        this.analysisErrorMessage = analysisErrorMessage;
    }

    public List<MethodCallChain> getCallChains() {
        return callChains;
    }

    public void setCallChains(List<MethodCallChain> callChains) {
        this.callChains = callChains;
    }

    public List<ConstraintSpecification> getConstraintsFound() {
        return constraintsFound;
    }

    public void setConstraintsFound(List<ConstraintSpecification> constraintsFound) {
        this.constraintsFound = constraintsFound;
    }

    public AnalysisMetrics getAnalysisMetrics() {
        return analysisMetrics;
    }

    public void setAnalysisMetrics(AnalysisMetrics analysisMetrics) {
        this.analysisMetrics = analysisMetrics;
    }

    // Nested Classes
    public static class MethodCallChain {
        @SerializedName("chain_id")
        private String chainId;

        @SerializedName("entry_point")
        private String entryPoint;

        @SerializedName("method_sequence")
        private List<String> methodSequence;

        @SerializedName("path_type")
        private String pathType; // e.g., "activity_lifecycle", "user_interaction"

        @SerializedName("is_reachable")
        private boolean isReachable;

        public MethodCallChain(String chainId, String entryPoint, List<String> methodSequence) {
            this.chainId = chainId;
            this.entryPoint = entryPoint;
            this.methodSequence = new ArrayList<>(methodSequence);
            this.isReachable = true; // Default to true, can be updated during analysis
        }

        // Getters and Setters
        public String getChainId() {
            return chainId;
        }

        public void setChainId(String chainId) {
            this.chainId = chainId;
        }

        public String getEntryPoint() {
            return entryPoint;
        }

        public void setEntryPoint(String entryPoint) {
            this.entryPoint = entryPoint;
        }

        public List<String> getMethodSequence() {
            return methodSequence;
        }

        public void setMethodSequence(List<String> methodSequence) {
            this.methodSequence = methodSequence;
        }

        public String getPathType() {
            return pathType;
        }

        public void setPathType(String pathType) {
            this.pathType = pathType;
        }

        public boolean isReachable() {
            return isReachable;
        }

        public void setReachable(boolean reachable) {
            isReachable = reachable;
        }
    }

    public static class ConstraintSpecification {
        @SerializedName("constraint_id")
        private String constraintId;

        @SerializedName("associated_call_chain")
        private String associatedCallChain;

        @SerializedName("boolean_logic_format")
        private String booleanLogicFormat;

        @SerializedName("business_context_format")
        private String businessContextFormat;

        @SerializedName("technical_details_format")
        private String technicalDetailsFormat;

        @SerializedName("constraint_complexity")
        private int constraintComplexity; // Number of conditions

        public ConstraintSpecification(String constraintId, String associatedCallChain) {
            this.constraintId = constraintId;
            this.associatedCallChain = associatedCallChain;
        }

        // Getters and Setters
        public String getConstraintId() {
            return constraintId;
        }

        public void setConstraintId(String constraintId) {
            this.constraintId = constraintId;
        }

        public String getAssociatedCallChain() {
            return associatedCallChain;
        }

        public void setAssociatedCallChain(String associatedCallChain) {
            this.associatedCallChain = associatedCallChain;
        }

        public String getBooleanLogicFormat() {
            return booleanLogicFormat;
        }

        public void setBooleanLogicFormat(String booleanLogicFormat) {
            this.booleanLogicFormat = booleanLogicFormat;
        }

        public String getBusinessContextFormat() {
            return businessContextFormat;
        }

        public void setBusinessContextFormat(String businessContextFormat) {
            this.businessContextFormat = businessContextFormat;
        }

        public String getTechnicalDetailsFormat() {
            return technicalDetailsFormat;
        }

        public void setTechnicalDetailsFormat(String technicalDetailsFormat) {
            this.technicalDetailsFormat = technicalDetailsFormat;
        }

        public int getConstraintComplexity() {
            return constraintComplexity;
        }

        public void setConstraintComplexity(int constraintComplexity) {
            this.constraintComplexity = constraintComplexity;
        }
    }

    public static class AnalysisMetrics {
        @SerializedName("analysis_start_time")
        private long analysisStartTime;

        @SerializedName("analysis_duration_ms")
        private long analysisDurationMs;

        @SerializedName("call_chains_discovered")
        private int callChainsDiscovered = 0;

        @SerializedName("constraints_extracted")
        private int constraintsExtracted = 0;

        public AnalysisMetrics() {
            this.analysisStartTime = System.currentTimeMillis();
        }

        public void setAnalysisCompleted() {
            this.analysisDurationMs = System.currentTimeMillis() - analysisStartTime;
        }

        // Getters and Setters
        public long getAnalysisStartTime() {
            return analysisStartTime;
        }

        public void setAnalysisStartTime(long analysisStartTime) {
            this.analysisStartTime = analysisStartTime;
        }

        public long getAnalysisDurationMs() {
            return analysisDurationMs;
        }

        public void setAnalysisDurationMs(long analysisDurationMs) {
            this.analysisDurationMs = analysisDurationMs;
        }

        public int getCallChainsDiscovered() {
            return callChainsDiscovered;
        }

        public void setCallChainsDiscovered(int callChainsDiscovered) {
            this.callChainsDiscovered = callChainsDiscovered;
        }

        public int getConstraintsExtracted() {
            return constraintsExtracted;
        }

        public void setConstraintsExtracted(int constraintsExtracted) {
            this.constraintsExtracted = constraintsExtracted;
        }
    }
}

// Enum for analysis status
enum AnalysisStatus {
    @SerializedName("pending")
    PENDING,
    @SerializedName("success")
    SUCCESS,
    @SerializedName("failed")
    FAILED,
    @SerializedName("timeout")
    TIMEOUT
}