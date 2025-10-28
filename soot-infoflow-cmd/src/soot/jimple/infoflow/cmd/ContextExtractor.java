package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Utility class for extracting Android-specific context information from Soot
 * analysis.
 * This class identifies lifecycle methods, resource literals, bundle arguments,
 * and class hierarchies.
 */
public class ContextExtractor {

    // Android lifecycle methods
    private static final Set<String> ANDROID_LIFECYCLE_METHODS = new HashSet<>(Arrays.asList(
            "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
            "onCreateView", "onViewCreated", "onDestroyView",
            "onStartCommand", "onBind", "onUnbind",
            "onReceive", "doWork"));

    // Android component base classes
    private static final Map<String, String> ANDROID_COMPONENT_HIERARCHY = new HashMap<>();
    static {
        ANDROID_COMPONENT_HIERARCHY.put("android.app.Activity", "Activity");
        ANDROID_COMPONENT_HIERARCHY.put("androidx.appcompat.app.AppCompatActivity", "Activity");
        ANDROID_COMPONENT_HIERARCHY.put("androidx.fragment.app.Fragment", "Fragment");
        ANDROID_COMPONENT_HIERARCHY.put("android.app.Fragment", "Fragment");
        ANDROID_COMPONENT_HIERARCHY.put("androidx.fragment.app.DialogFragment", "Fragment");
        ANDROID_COMPONENT_HIERARCHY.put("android.app.Service", "Service");
        ANDROID_COMPONENT_HIERARCHY.put("androidx.work.Worker", "Worker");
        ANDROID_COMPONENT_HIERARCHY.put("android.content.BroadcastReceiver", "Receiver");
        ANDROID_COMPONENT_HIERARCHY.put("android.app.Dialog", "Dialog");
        ANDROID_COMPONENT_HIERARCHY.put("androidx.appcompat.app.AlertDialog", "Dialog");
    }

    // Resource pattern matchers
    private static final Pattern R_LAYOUT_PATTERN = Pattern.compile("R\\$layout.*?int\\s+(\\w+)");
    private static final Pattern R_STRING_PATTERN = Pattern.compile("R\\$string.*?int\\s+(\\w+)");
    private static final Pattern R_ID_PATTERN = Pattern.compile("R\\$id.*?int\\s+(\\w+)");

    /**
     * Extracts lifecycle method name from a SootMethod if it's an Android lifecycle
     * method.
     */
    public static String extractLifecycleMethod(SootMethod method) {
        if (method == null)
            return null;

        String methodName = method.getName();
        if (ANDROID_LIFECYCLE_METHODS.contains(methodName)) {
            return methodName;
        }

        return null;
    }

    /**
     * Determines the Android component hierarchy for a given class.
     */
    public static String determineClassHierarchy(SootClass sootClass) {
        if (sootClass == null)
            return "Object";

        try {
            // Check direct mapping first
            String className = sootClass.getName();
            if (ANDROID_COMPONENT_HIERARCHY.containsKey(className)) {
                return ANDROID_COMPONENT_HIERARCHY.get(className);
            }

            // Check inheritance hierarchy
            if (Scene.v().hasActiveHierarchy()) {
                Hierarchy hierarchy = Scene.v().getActiveHierarchy();

                for (Map.Entry<String, String> entry : ANDROID_COMPONENT_HIERARCHY.entrySet()) {
                    String baseClassName = entry.getKey();
                    String componentType = entry.getValue();

                    try {
                        SootClass baseClass = Scene.v().getSootClassUnsafe(baseClassName);
                        if (baseClass != null && hierarchy.isClassSubclassOf(sootClass, baseClass)) {
                            return componentType;
                        }
                    } catch (Exception e) {
                        // Class not found or hierarchy check failed, continue
                    }
                }
            }

            // Fallback: check simple name patterns
            String simpleName = sootClass.getName();
            if (simpleName.contains("Activity"))
                return "Activity";
            if (simpleName.contains("Fragment"))
                return "Fragment";
            if (simpleName.contains("Service"))
                return "Service";
            if (simpleName.contains("Worker"))
                return "Worker";
            if (simpleName.contains("Receiver"))
                return "Receiver";
            if (simpleName.contains("Dialog"))
                return "Dialog";

        } catch (Exception e) {
            System.err.println("Error determining class hierarchy for " + sootClass.getName() + ": " + e.getMessage());
        }

        return "Object";
    }

    /**
     * Extracts resource literals from a Jimple statement.
     */
    public static List<String> extractResourceLiterals(Unit unit) {
        List<String> resources = new ArrayList<>();

        if (unit == null)
            return resources;

        try {
            String unitStr = unit.toString();

            // Extract R.layout.* references
            Matcher layoutMatcher = R_LAYOUT_PATTERN.matcher(unitStr);
            while (layoutMatcher.find()) {
                resources.add("R.layout." + layoutMatcher.group(1));
            }

            // Extract R.string.* references
            Matcher stringMatcher = R_STRING_PATTERN.matcher(unitStr);
            while (stringMatcher.find()) {
                resources.add("R.string." + stringMatcher.group(1));
            }

            // Extract R.id.* references
            Matcher idMatcher = R_ID_PATTERN.matcher(unitStr);
            while (idMatcher.find()) {
                resources.add("R.id." + idMatcher.group(1));
            }

            // Extract string literals (potential routes)
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value rightOp = assign.getRightOp();

                if (rightOp instanceof StringConstant) {
                    StringConstant strConst = (StringConstant) rightOp;
                    String value = strConst.value;

                    // Filter for likely route strings (contain /, not empty, reasonable length)
                    if (value.contains("/") && value.length() > 1 && value.length() < 100) {
                        resources.add("route:" + value);
                    }
                }
            }

            // Extract static field references for resources
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value rightOp = assign.getRightOp();

                if (rightOp instanceof StaticFieldRef) {
                    StaticFieldRef fieldRef = (StaticFieldRef) rightOp;
                    SootField field = fieldRef.getField();
                    String fieldName = field.toString();

                    // Check for R.* patterns
                    if (fieldName.contains("R$layout")) {
                        resources.add("R.layout." + field.getName());
                    } else if (fieldName.contains("R$string")) {
                        resources.add("R.string." + field.getName());
                    } else if (fieldName.contains("R$id")) {
                        resources.add("R.id." + field.getName());
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Error extracting resources from unit: " + unit + " - " + e.getMessage());
        }

        return resources;
    }

    /**
     * Scans a method for Bundle/Intent argument construction patterns.
     */
    public static Map<String, String> extractBundleArguments(SootMethod method) {
        Map<String, String> bundleArgs = new HashMap<>();

        if (method == null || !method.hasActiveBody()) {
            return bundleArgs;
        }

        try {
            Body body = method.getActiveBody();

            for (Unit unit : body.getUnits()) {
                if (unit instanceof InvokeStmt || unit instanceof AssignStmt) {
                    InvokeExpr invokeExpr = null;

                    if (unit instanceof InvokeStmt) {
                        invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                    } else if (unit instanceof AssignStmt) {
                        AssignStmt assign = (AssignStmt) unit;
                        if (assign.getRightOp() instanceof InvokeExpr) {
                            invokeExpr = (InvokeExpr) assign.getRightOp();
                        }
                    }

                    if (invokeExpr != null) {
                        extractBundleArgumentsFromInvoke(invokeExpr, bundleArgs);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println(
                    "Error extracting bundle arguments from method " + method.getSignature() + ": " + e.getMessage());
        }

        return bundleArgs;
    }

    /**
     * Helper method to extract bundle arguments from invoke expressions.
     */
    private static void extractBundleArgumentsFromInvoke(InvokeExpr invokeExpr, Map<String, String> bundleArgs) {
        String methodSig = invokeExpr.getMethod().getSignature();

        // Bundle.putString, Bundle.putInt, etc.
        if (methodSig.contains("android.os.Bundle") && methodSig.contains("put")) {
            if (invokeExpr.getArgCount() >= 2) {
                Value keyValue = invokeExpr.getArg(0);

                if (keyValue instanceof StringConstant) {
                    String key = ((StringConstant) keyValue).value;
                    String type = extractBundleArgType(methodSig);
                    bundleArgs.put(key, type);
                }
            }
        }

        // Intent.putExtra
        if (methodSig.contains("android.content.Intent") && methodSig.contains("putExtra")) {
            if (invokeExpr.getArgCount() >= 2) {
                Value keyValue = invokeExpr.getArg(0);

                if (keyValue instanceof StringConstant) {
                    String key = ((StringConstant) keyValue).value;
                    String type = extractIntentArgType(methodSig);
                    bundleArgs.put(key, type);
                }
            }
        }
    }

    /**
     * Extracts the argument type from Bundle method signatures.
     */
    private static String extractBundleArgType(String methodSig) {
        if (methodSig.contains("putString"))
            return "String";
        if (methodSig.contains("putInt"))
            return "int";
        if (methodSig.contains("putBoolean"))
            return "boolean";
        if (methodSig.contains("putLong"))
            return "long";
        if (methodSig.contains("putFloat"))
            return "float";
        if (methodSig.contains("putDouble"))
            return "double";
        if (methodSig.contains("putParcelable"))
            return "Parcelable";
        if (methodSig.contains("putSerializable"))
            return "Serializable";
        return "Object";
    }

    /**
     * Extracts the argument type from Intent method signatures.
     */
    private static String extractIntentArgType(String methodSig) {
        // Intent.putExtra has overloads for different types
        if (methodSig.contains("java.lang.String,java.lang.String"))
            return "String";
        if (methodSig.contains("java.lang.String,int"))
            return "int";
        if (methodSig.contains("java.lang.String,boolean"))
            return "boolean";
        if (methodSig.contains("java.lang.String,long"))
            return "long";
        if (methodSig.contains("java.lang.String,float"))
            return "float";
        if (methodSig.contains("java.lang.String,double"))
            return "double";
        return "Object";
    }

    /**
     * Utility method to get containing class name from a SootMethod.
     */
    public static String getContainingClassName(SootMethod method) {
        if (method == null || method.getDeclaringClass() == null) {
            return null;
        }

        SootClass declaringClass = method.getDeclaringClass();
        String fullName = declaringClass.getName();

        // Return simple class name (last part after final dot)
        int lastDot = fullName.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < fullName.length() - 1) {
            return fullName.substring(lastDot + 1);
        }

        return fullName;
    }

    /**
     * Checks if a method is likely to contain UI-related allocations.
     */
    public static boolean isUIRelatedMethod(SootMethod method) {
        if (method == null)
            return false;

        String methodName = method.getName();
        String className = method.getDeclaringClass().getName();

        // Lifecycle methods
        if (ANDROID_LIFECYCLE_METHODS.contains(methodName)) {
            return true;
        }

        // UI-related method names
        if (methodName.contains("View") || methodName.contains("Layout") ||
                methodName.contains("inflate") || methodName.contains("findViewById")) {
            return true;
        }

        // UI-related class contexts
        if (className.contains("Activity") || className.contains("Fragment") ||
                className.contains("Dialog")) {
            return true;
        }

        return false;
    }
}