package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Represents a complete execution path from an entry point to a target method,
 * including all constraints that must be satisfied along the path.
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

    /**
     * Generate a human-readable description of this path
     */
    public String getPathDescription() {
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
            sb.append("Constraints:\n");
            for (int i = 0; i < constraints.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(constraints.get(i).getConditionExpression())
                        .append("\n");
            }
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
     * Generate a concise summary of this path
     */
    public String getPathSummary() {
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

        // Add constraint summary
        if (!constraints.isEmpty()) {
            List<String> constraintSummaries = constraints.stream()
                    .map(c -> c.getConditionExpression())
                    .collect(Collectors.toList());

            if (constraintSummaries.size() <= 3) {
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
     */
    public static Map<SootMethod, List<ConstraintPath>> groupByEntryPoint(List<ConstraintPath> paths) {
        return paths.stream()
                .collect(Collectors.groupingBy(ConstraintPath::getEntryPoint));
    }

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