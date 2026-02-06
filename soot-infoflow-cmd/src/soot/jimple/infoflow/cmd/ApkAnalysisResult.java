package soot.jimple.infoflow.cmd;

import com.google.gson.annotations.SerializedName;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Complete analysis results for a single APK, containing all dangerous APIs
 * found
 * and their corresponding constraint analysis results.
 */
public class ApkAnalysisResult {

    @SerializedName("apk_metadata")
    private ApkMetadata apkMetadata;

    @SerializedName("dangerous_apis_found")
    private List<DangerousApiAnalysisResult> dangerousApisFound;

    @SerializedName("analysis_summary")
    private AnalysisSummary analysisSummary;

    @SerializedName("analysis_timestamp")
    private String analysisTimestamp;

    // Constructors
    public ApkAnalysisResult(String apkName, String apkPath, String packageName) {
        this.apkMetadata = new ApkMetadata(apkName, apkPath, packageName);
        this.dangerousApisFound = new ArrayList<>();
        this.analysisSummary = new AnalysisSummary();
        this.analysisTimestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    // Add dangerous API analysis result
    public void addDangerousApiResult(DangerousApiAnalysisResult result) {
        this.dangerousApisFound.add(result);
        updateSummary(result);
    }

    // Update analysis summary statistics
    private void updateSummary(DangerousApiAnalysisResult result) {
        analysisSummary.totalDangerousApis++;

        if (result.getAnalysisStatus() == AnalysisStatus.SUCCESS) {
            analysisSummary.successfulAnalyses++;
            analysisSummary.totalConstraintsFound += result.getConstraintsFound().size();
            analysisSummary.totalCallChainsFound += result.getCallChains().size();
        } else {
            analysisSummary.failedAnalyses++;
        }

        // Update category counts
        String category = result.getApiCategory();
        analysisSummary.categoryCounts.merge(category, 1, Integer::sum);
    }

    // Mark overall analysis as completed
    public void setAnalysisCompleted(boolean success, String errorMessage) {
        analysisSummary.analysisCompleted = success;
        analysisSummary.errorMessage = errorMessage;
    }

    // Getters and Setters
    public ApkMetadata getApkMetadata() {
        return apkMetadata;
    }

    public void setApkMetadata(ApkMetadata apkMetadata) {
        this.apkMetadata = apkMetadata;
    }

    public List<DangerousApiAnalysisResult> getDangerousApisFound() {
        return dangerousApisFound;
    }

    public void setDangerousApisFound(List<DangerousApiAnalysisResult> dangerousApisFound) {
        this.dangerousApisFound = dangerousApisFound;
    }

    public AnalysisSummary getAnalysisSummary() {
        return analysisSummary;
    }

    public void setAnalysisSummary(AnalysisSummary analysisSummary) {
        this.analysisSummary = analysisSummary;
    }

    public String getAnalysisTimestamp() {
        return analysisTimestamp;
    }

    public void setAnalysisTimestamp(String analysisTimestamp) {
        this.analysisTimestamp = analysisTimestamp;
    }

    // Nested Classes
    public static class ApkMetadata {
        @SerializedName("apk_name")
        private String apkName;

        @SerializedName("apk_path")
        private String apkPath;

        @SerializedName("package_name")
        private String packageName;

        @SerializedName("file_size_bytes")
        private long fileSizeBytes;

        @SerializedName("file_hash")
        private String fileHash; // Optional: SHA256 hash for verification

        public ApkMetadata(String apkName, String apkPath, String packageName) {
            this.apkName = apkName;
            this.apkPath = apkPath;
            this.packageName = packageName != null ? packageName : "unknown";
            this.fileSizeBytes = 0; // Will be set later if needed
            this.fileHash = null; // Will be computed later if needed
        }

        // Getters and Setters
        public String getApkName() {
            return apkName;
        }

        public void setApkName(String apkName) {
            this.apkName = apkName;
        }

        public String getApkPath() {
            return apkPath;
        }

        public void setApkPath(String apkPath) {
            this.apkPath = apkPath;
        }

        public String getPackageName() {
            return packageName;
        }

        public void setPackageName(String packageName) {
            this.packageName = packageName;
        }

        public long getFileSizeBytes() {
            return fileSizeBytes;
        }

        public void setFileSizeBytes(long fileSizeBytes) {
            this.fileSizeBytes = fileSizeBytes;
        }

        public String getFileHash() {
            return fileHash;
        }

        public void setFileHash(String fileHash) {
            this.fileHash = fileHash;
        }
    }

    public static class AnalysisSummary {
        @SerializedName("analysis_completed")
        private boolean analysisCompleted = false;

        @SerializedName("error_message")
        private String errorMessage = null;

        @SerializedName("total_dangerous_apis")
        private int totalDangerousApis = 0;

        @SerializedName("successful_analyses")
        private int successfulAnalyses = 0;

        @SerializedName("failed_analyses")
        private int failedAnalyses = 0;

        @SerializedName("total_constraints_found")
        private int totalConstraintsFound = 0;

        @SerializedName("total_call_chains_found")
        private int totalCallChainsFound = 0;

        @SerializedName("category_counts")
        private Map<String, Integer> categoryCounts = new HashMap<>();

        // Getters and Setters
        public boolean isAnalysisCompleted() {
            return analysisCompleted;
        }

        public void setAnalysisCompleted(boolean analysisCompleted) {
            this.analysisCompleted = analysisCompleted;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public int getTotalDangerousApis() {
            return totalDangerousApis;
        }

        public void setTotalDangerousApis(int totalDangerousApis) {
            this.totalDangerousApis = totalDangerousApis;
        }

        public int getSuccessfulAnalyses() {
            return successfulAnalyses;
        }

        public void setSuccessfulAnalyses(int successfulAnalyses) {
            this.successfulAnalyses = successfulAnalyses;
        }

        public int getFailedAnalyses() {
            return failedAnalyses;
        }

        public void setFailedAnalyses(int failedAnalyses) {
            this.failedAnalyses = failedAnalyses;
        }

        public int getTotalConstraintsFound() {
            return totalConstraintsFound;
        }

        public void setTotalConstraintsFound(int totalConstraintsFound) {
            this.totalConstraintsFound = totalConstraintsFound;
        }

        public int getTotalCallChainsFound() {
            return totalCallChainsFound;
        }

        public void setTotalCallChainsFound(int totalCallChainsFound) {
            this.totalCallChainsFound = totalCallChainsFound;
        }

        public Map<String, Integer> getCategoryCounts() {
            return categoryCounts;
        }

        public void setCategoryCounts(Map<String, Integer> categoryCounts) {
            this.categoryCounts = categoryCounts;
        }
    }
}