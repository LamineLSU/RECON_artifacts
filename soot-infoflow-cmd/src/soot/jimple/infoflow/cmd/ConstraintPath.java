package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;
import java.util.stream.Collectors;
import soot.SootMethod;

/**
 * Represents a complete execution path from an entry point to a target method,
 * including all constraints that must be satisfied along the path.
 * Now supports three output formats and constraint amalgamation.
 */
public class ConstraintPath {
    private final String pathId;
    private final SootMethod targetMethod;
    private final SootMethod entryPoint;
    private final List<SootMethod> methodSequence;
    private final List<Constraint> constraints;
    private final PathType pathType;
    private final Map<String, Object> metadata;
    private boolean isValidPath;
    private String invalidationReason;

    public ConstraintPath(String pathId, SootMethod targetMethod, SootMethod entryPoint, PathType pathType) {
        this.pathId = pathId;
        this.targetMethod = targetMethod;
        this.entryPoint = entryPoint;
        this.pathType = pathType;
        this.methodSequence = new ArrayList<>();
        this.constraints = new ArrayList<>();
        this.metadata = new HashMap<>();
        this.isValidPath = true;
        this.invalidationReason = null;

        // Add entry point to method sequence
        if (entryPoint != null) {
            methodSequence.add(entryPoint);
        }
    }

    // New constructor for updated system
    public ConstraintPath(String pathId, SootMethod targetMethod, List<SootMethod> methodSequence,
            List<Constraint> constraints, boolean isValid) {
        this.pathId = pathId;
        this.targetMethod = targetMethod;
        this.entryPoint = methodSequence.isEmpty() ? null : methodSequence.get(0);
        this.methodSequence = new ArrayList<>(methodSequence);
        this.constraints = new ArrayList<>(constraints);
        this.pathType = determinePathType();
        this.metadata = new HashMap<>();
        this.isValidPath = isValid;
        this.invalidationReason = isValid ? null : "Path validation failed";
    }

    /**
     * Add a method to the execution sequence
     */
    public void addMethodToSequence(SootMethod method) {
        if (method != null && !methodSequence.contains(method)) {
            methodSequence.add(method);
        }
    }

    /**
     * Add a constraint to this path
     */
    public void addConstraint(Constraint constraint) {
        if (constraint == null)
            return;

        // Check compatibility with existing constraints
        for (Constraint existingConstraint : constraints) {
            if (!constraint.isCompatibleWith(existingConstraint)) {
                invalidatePath("Incompatible constraint: " + constraint.getHumanReadableCondition() +
                        " conflicts with " + existingConstraint.getHumanReadableCondition());
                return;
            }
        }

        constraints.add(constraint);
    }

    /**
     * Add multiple constraints to this path
     */
    public void addConstraints(List<Constraint> newConstraints) {
        for (Constraint constraint : newConstraints) {
            addConstraint(constraint);
            if (!isValidPath)
                break; // Stop if path becomes invalid
        }
    }

    /**
     * Mark this path as invalid
     */
    public void invalidatePath(String reason) {
        this.isValidPath = false;
        this.invalidationReason = reason;
    }

    /**
     * Get constraints by type
     */
    public List<Constraint> getConstraintsByType(ConstraintType type) {
        return constraints.stream()
                .filter(c -> c.getType() == type)
                .collect(Collectors.toList());
    }

    /**
     * Get constraints from a specific method
     */
    public List<Constraint> getConstraintsFromMethod(SootMethod method) {
        return constraints.stream()
                .filter(c -> c.getSourceMethod().equals(method))
                .collect(Collectors.toList());
    }

    /**
     * Check if path contains a specific constraint type
     */
    public boolean hasConstraintType(ConstraintType type) {
        return constraints.stream().anyMatch(c -> c.getType() == type);
    }

    /**
     * Get the length of the path (number of methods in sequence)
     */
    public int getPathLength() {
        return methodSequence.size();
    }

    /**
     * Get the number of constraints on this path
     */
    public int getConstraintCount() {
        return constraints.size();
    }

    // ===== NEW: THREE-FORMAT CONSTRAINT ACCESS =====

    /**
     * Get all constraints in Format 1 (Boolean Logic)
     */
    public List<String> getConstraintsFormat1() {
        return constraints.stream()
                .map(Constraint::getFormat1)
                .collect(Collectors.toList());
    }

    /**
     * Get all constraints in Format 2 (Business Context)
     */
    public List<String> getConstraintsFormat2() {
        return constraints.stream()
                .map(Constraint::getFormat2)
                .collect(Collectors.toList());
    }

    /**
     * Get all constraints in Format 3 (Technical Details)
     */
    public List<String> getConstraintsFormat3() {
        return constraints.stream()
                .map(Constraint::getFormat3)
                .collect(Collectors.toList());
    }

    /**
     * Get combined constraints in specified format
     */
    public String getCombinedConstraints(ConstraintFormat format) {
        List<String> constraintStrings;

        switch (format) {
            case FORMAT_1:
                constraintStrings = getConstraintsFormat1();
                break;
            case FORMAT_2:
                constraintStrings = getConstraintsFormat2();
                break;
            case FORMAT_3:
                constraintStrings = getConstraintsFormat3();
                break;
            default:
                constraintStrings = constraints.stream()
                        .map(Constraint::getHumanReadableCondition)
                        .collect(Collectors.toList());
        }

        return combineConstraints(constraintStrings);
    }

    /**
     * Get logical expression combining all constraints using boolean logic
     */
    public String getLogicalExpression() {
        if (constraints.isEmpty()) {
            return "true"; // No constraints means path is always accessible
        }

        List<String> logicalConstraints = getConstraintsFormat1();
        return combineConstraintsWithLogic(logicalConstraints);
    }

    // ===== NEW: CONSTRAINT AMALGAMATION LOGIC =====

    /**
     * Combine constraints into a single logical expression
     */
    private String combineConstraints(List<String> constraintStrings) {
        if (constraintStrings.isEmpty()) {
            return "";
        }

        if (constraintStrings.size() == 1) {
            return constraintStrings.get(0);
        }

        // For multiple constraints, combine with AND logic
        return constraintStrings.stream()
                .map(c -> "(" + c + ")")
                .collect(Collectors.joining(" AND "));
    }

    /**
     * Combine constraints with sophisticated boolean logic
     */
    private String combineConstraintsWithLogic(List<String> logicalConstraints) {
        if (logicalConstraints.isEmpty()) {
            return "true";
        }

        if (logicalConstraints.size() == 1) {
            return logicalConstraints.get(0);
        }

        // Group constraints by method for better logical structure
        Map<SootMethod, List<String>> constraintsByMethod = new HashMap<>();

        for (int i = 0; i < constraints.size() && i < logicalConstraints.size(); i++) {
            SootMethod method = constraints.get(i).getSourceMethod();
            String logicalConstraint = logicalConstraints.get(i);

            constraintsByMethod.computeIfAbsent(method, k -> new ArrayList<>()).add(logicalConstraint);
        }

        // Combine constraints within each method using AND, then combine methods
        List<String> methodExpressions = new ArrayList<>();

        for (Map.Entry<SootMethod, List<String>> entry : constraintsByMethod.entrySet()) {
            List<String> methodConstraints = entry.getValue();

            if (methodConstraints.size() == 1) {
                methodExpressions.add(methodConstraints.get(0));
            } else {
                String combinedMethodConstraints = methodConstraints.stream()
                        .map(c -> "(" + c + ")")
                        .collect(Collectors.joining(" AND "));
                methodExpressions.add("(" + combinedMethodConstraints + ")");
            }
        }

        // Combine method expressions with AND
        return methodExpressions.stream()
                .collect(Collectors.joining(" AND "));
    }

    /**
     * Determine path type based on entry point and methods
     */
    private PathType determinePathType() {
        if (entryPoint == null) {
            return PathType.OTHER;
        }

        String className = entryPoint.getDeclaringClass().getName();
        String methodName = entryPoint.getName();

        if (methodName.contains("onCreate") || methodName.contains("onStart") || methodName.contains("onResume")) {
            return PathType.ACTIVITY_LIFECYCLE;
        } else if (className.contains("Service")) {
            return PathType.SERVICE_LIFECYCLE;
        } else if (className.contains("Receiver")) {
            return PathType.BROADCAST_RECEIVER;
        } else if (className.contains("Provider")) {
            return PathType.CONTENT_PROVIDER;
        } else if (methodName.contains("onClick") || methodName.contains("onTouch")) {
            return PathType.USER_INTERACTION;
        } else if (methodName.contains("run") || className.contains("Thread")) {
            return PathType.THREAD_EXECUTION;
        } else {
            return PathType.OTHER;
        }
    }

    /**
     * Generate a human-readable description of this path with format selection
     */
    public String getPathDescription(ConstraintFormat format) {
        StringBuilder sb = new StringBuilder();

        sb.append("Path ").append(pathId).append(" (").append(pathType).append("):\n");
        sb.append("Entry: ").append(entryPoint != null ? entryPoint.getSignature() : "Unknown").append("\n");
        sb.append("Target: ").append(targetMethod.getSignature()).append("\n");
        sb.append("Valid: ").append(isValidPath);

        if (!isValidPath) {
            sb.append(" (").append(invalidationReason).append(")");
        }

        sb.append("\n");

        if (!constraints.isEmpty()) {
            sb.append("Constraints (").append(getFormatName(format)).append("):\n");
            List<String> formatConstraints = getConstraintsInFormat(format);

            for (int i = 0; i < formatConstraints.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(formatConstraints.get(i)).append("\n");
            }

            sb.append("\nLogical Expression: ").append(getCombinedConstraints(format)).append("\n");
        }

        if (methodSequence.size() > 1) {
            sb.append("Method Sequence:\n");
            for (int i = 0; i < methodSequence.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(methodSequence.get(i).getName());
                if (i < methodSequence.size() - 1) {
                    sb.append(" →");
                }
                sb.append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Generate a human-readable description of this path (default format)
     */
    public String getPathDescription() {
        return getPathDescription(ConstraintFormat.FORMAT_2); // Default to business context
    }

    /**
     * Generate a concise summary of this path with format selection
     */
    public String getPathSummary(ConstraintFormat format) {
        StringBuilder sb = new StringBuilder();

        sb.append("Path ").append(pathId).append(": ");

        if (!isValidPath) {
            sb.append("INVALID - ").append(invalidationReason);
            return sb.toString();
        }

        // Add entry info
        if (entryPoint != null) {
            sb.append(getSimpleMethodName(entryPoint)).append(" → ");
        }

        // Add constraint summary in specified format
        if (!constraints.isEmpty()) {
            List<String> constraintSummaries = getConstraintsInFormat(format);

            if (constraintSummaries.size() <= 50) {
                sb.append("[").append(String.join(" AND ", constraintSummaries)).append("] → ");
            } else {
                sb.append("[").append(constraintSummaries.get(0)).append(" AND ")
                        .append(constraintSummaries.size() - 1).append(" more] → ");
            }
        }

        sb.append(getSimpleMethodName(targetMethod));

        return sb.toString();
    }

    /**
     * Generate a concise summary of this path (default format)
     */
    public String getPathSummary() {
        return getPathSummary(ConstraintFormat.FORMAT_2);
    }

    /**
     * Get constraints in specified format
     */
    private List<String> getConstraintsInFormat(ConstraintFormat format) {
        switch (format) {
            case FORMAT_1:
                return getConstraintsFormat1();
            case FORMAT_2:
                return getConstraintsFormat2();
            case FORMAT_3:
                return getConstraintsFormat3();
            default:
                return constraints.stream()
                        .map(Constraint::getHumanReadableCondition)
                        .collect(Collectors.toList());
        }
    }

    /**
     * Get human-readable format name
     */
    private String getFormatName(ConstraintFormat format) {
        switch (format) {
            case FORMAT_1:
                return "Boolean Logic";
            case FORMAT_2:
                return "Business Context";
            case FORMAT_3:
                return "Technical Details";
            default:
                return "Default";
        }
    }

    /**
     * Merge this path with another path (for path optimization)
     */
    public ConstraintPath mergeWith(ConstraintPath otherPath) {
        if (!targetMethod.equals(otherPath.targetMethod)) {
            throw new IllegalArgumentException("Cannot merge paths with different target methods");
        }

        String mergedId = pathId + "+" + otherPath.pathId;
        ConstraintPath mergedPath = new ConstraintPath(mergedId, targetMethod, entryPoint, PathType.MERGED);

        // Merge method sequences
        Set<SootMethod> allMethods = new LinkedHashSet<>(methodSequence);
        allMethods.addAll(otherPath.methodSequence);
        mergedPath.methodSequence.addAll(allMethods);

        // Merge constraints (compatibility checking will happen in addConstraints)
        mergedPath.addConstraints(constraints);
        mergedPath.addConstraints(otherPath.constraints);

        // Merge metadata
        mergedPath.metadata.putAll(metadata);
        mergedPath.metadata.putAll(otherPath.metadata);

        return mergedPath;
    }

    /**
     * Add metadata to this path
     */
    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }

    /**
     * Get metadata value
     */
    public Object getMetadata(String key) {
        return metadata.get(key);
    }

    /**
     * Create a copy of this path
     */
    public ConstraintPath copy() {
        ConstraintPath copy = new ConstraintPath(pathId + "_copy", targetMethod, entryPoint, pathType);
        copy.methodSequence.addAll(methodSequence);
        copy.constraints.addAll(constraints);
        copy.metadata.putAll(metadata);
        copy.isValidPath = isValidPath;
        copy.invalidationReason = invalidationReason;
        return copy;
    }

    /**
     * Helper method to get simple method name for display
     */
    private String getSimpleMethodName(SootMethod method) {
        if (method == null)
            return "null";

        String className = method.getDeclaringClass().getShortName();
        String methodName = method.getName();

        // Handle special cases
        if (methodName.equals("<init>")) {
            return className + "()";
        } else if (methodName.contains("dummyMainMethod")) {
            return "DummyMain";
        }

        return className + "." + methodName + "()";
    }

    // Getters
    public String getPathId() {
        return pathId;
    }

    public SootMethod getTargetMethod() {
        return targetMethod;
    }

    public SootMethod getEntryPoint() {
        return entryPoint;
    }

    public List<SootMethod> getMethodSequence() {
        return Collections.unmodifiableList(methodSequence);
    }

    public List<Constraint> getConstraints() {
        return Collections.unmodifiableList(constraints);
    }

    public PathType getPathType() {
        return pathType;
    }

    public boolean isValidPath() {
        return isValidPath;
    }

    public String getInvalidationReason() {
        return invalidationReason;
    }

    public Map<String, Object> getMetadata() {
        return Collections.unmodifiableMap(metadata);
    }

    @Override
    public String toString() {
        return getPathSummary();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ConstraintPath that = (ConstraintPath) o;
        return Objects.equals(pathId, that.pathId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pathId);
    }
}

/**
 * Enumeration of constraint output formats
 */
enum ConstraintFormat {
    FORMAT_1, // Boolean logic format
    FORMAT_2, // Business context format
    FORMAT_3, // Technical details format
    DEFAULT // Default human-readable format
}

/**
 * Enumeration of path types for categorization
 */
enum PathType {
    ACTIVITY_LIFECYCLE, // Path through activity lifecycle methods
    SERVICE_LIFECYCLE, // Path through service lifecycle methods
    BROADCAST_RECEIVER, // Path through broadcast receiver
    CONTENT_PROVIDER, // Path through content provider
    USER_INTERACTION, // Path triggered by user interaction
    SYSTEM_CALLBACK, // Path triggered by system callback
    THREAD_EXECUTION, // Path in background thread
    MERGED, // Merged from multiple paths
    OTHER // Other/unknown path type
}

/**
 * Utility class for path operations
 */
class ConstraintPathUtils {

    /**
     * Find common constraints between multiple paths
     */
    public static List<Constraint> findCommonConstraints(List<ConstraintPath> paths) {
        if (paths.isEmpty())
            return new ArrayList<>();

        List<Constraint> commonConstraints = new ArrayList<>(paths.get(0).getConstraints());

        for (int i = 1; i < paths.size(); i++) {
            commonConstraints.retainAll(paths.get(i).getConstraints());
        }

        return commonConstraints;
    }

    /**
     * Group paths by their entry points
     * 
     * public static Map<SootMethod, List<ConstraintPath>>
     * groupByEntryPoint(List<ConstraintPath> paths) {
     * return paths.stream()
     * .collect(Collectors.groupingBy(ConstraintPath::getEntryPoint));
     * }
     */
    /**
     * Filter paths by constraint type
     */
    public static List<ConstraintPath> filterByConstraintType(List<ConstraintPath> paths, ConstraintType type) {
        return paths.stream()
                .filter(path -> path.hasConstraintType(type))
                .collect(Collectors.toList());
    }

    /**
     * Get statistics about a collection of paths
     */
    public static PathStatistics getPathStatistics(List<ConstraintPath> paths) {
        return new PathStatistics(paths);
    }

    /**
     * Combine multiple paths into a comprehensive constraint expression
     */
    public static String getCombinedLogicalExpression(List<ConstraintPath> paths, ConstraintFormat format) {
        if (paths.isEmpty()) {
            return "false"; // No paths means target is unreachable
        }

        List<String> pathExpressions = paths.stream()
                .filter(ConstraintPath::isValidPath)
                .map(path -> "(" + path.getCombinedConstraints(format) + ")")
                .collect(Collectors.toList());

        if (pathExpressions.isEmpty()) {
            return "false"; // No valid paths
        }

        if (pathExpressions.size() == 1) {
            return pathExpressions.get(0);
        }

        // Multiple paths are combined with OR logic (any path can reach target)
        return pathExpressions.stream().collect(Collectors.joining(" OR "));
    }
}

/**
 * Statistical information about a collection of constraint paths
 */
class PathStatistics {
    private final int totalPaths;
    private final int validPaths;
    private final int invalidPaths;
    private final double averageConstraints;
    private final double averagePathLength;
    private final Map<ConstraintType, Integer> constraintTypeCounts;
    private final Map<PathType, Integer> pathTypeCounts;

    public PathStatistics(List<ConstraintPath> paths) {
        this.totalPaths = paths.size();
        this.validPaths = (int) paths.stream().filter(ConstraintPath::isValidPath).count();
        this.invalidPaths = totalPaths - validPaths;

        this.averageConstraints = paths.stream()
                .mapToInt(ConstraintPath::getConstraintCount)
                .average()
                .orElse(0.0);

        this.averagePathLength = paths.stream()
                .mapToInt(ConstraintPath::getPathLength)
                .average()
                .orElse(0.0);

        this.constraintTypeCounts = new HashMap<>();
        this.pathTypeCounts = new HashMap<>();

        // Count constraint types
        paths.stream()
                .flatMap(path -> path.getConstraints().stream())
                .forEach(constraint -> constraintTypeCounts.merge(constraint.getType(), 1, Integer::sum));

        // Count path types
        paths.forEach(path -> pathTypeCounts.merge(path.getPathType(), 1, Integer::sum));
    }

    // Getters
    public int getTotalPaths() {
        return totalPaths;
    }

    public int getValidPaths() {
        return validPaths;
    }

    public int getInvalidPaths() {
        return invalidPaths;
    }

    public double getAverageConstraints() {
        return averageConstraints;
    }

    public double getAveragePathLength() {
        return averagePathLength;
    }

    public Map<ConstraintType, Integer> getConstraintTypeCounts() {
        return Collections.unmodifiableMap(constraintTypeCounts);
    }

    public Map<PathType, Integer> getPathTypeCounts() {
        return Collections.unmodifiableMap(pathTypeCounts);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Path Statistics:\n");
        sb.append("  Total paths: ").append(totalPaths).append("\n");
        sb.append("  Valid paths: ").append(validPaths).append("\n");
        sb.append("  Invalid paths: ").append(invalidPaths).append("\n");
        sb.append("  Average constraints per path: ").append(String.format("%.2f", averageConstraints)).append("\n");
        sb.append("  Average path length: ").append(String.format("%.2f", averagePathLength)).append("\n");

        if (!constraintTypeCounts.isEmpty()) {
            sb.append("  Constraint types:\n");
            constraintTypeCounts
                    .forEach((type, count) -> sb.append("    ").append(type).append(": ").append(count).append("\n"));
        }

        if (!pathTypeCounts.isEmpty()) {
            sb.append("  Path types:\n");
            pathTypeCounts
                    .forEach((type, count) -> sb.append("    ").append(type).append(": ").append(count).append("\n"));
        }

        return sb.toString();
    }
}