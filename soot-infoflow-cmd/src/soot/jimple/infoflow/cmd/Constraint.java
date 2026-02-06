package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * Abstract base class representing execution constraints that must be satisfied
 * to reach a target method. Constraints are extracted from control flow conditions
 * and converted to human-readable form using LLM analysis.
 * Now supports three output formats for different analysis needs.
 */
public abstract class Constraint {
    protected final String id;
    protected final SootMethod sourceMethod;
    protected final Unit sourceUnit;
    protected final String humanReadableCondition;
    protected final ConstraintType type;
    
    // New: Three-format support
    protected final String format1; // Boolean logic
    protected final String format2; // Business context
    protected final String format3; // Technical details

    public Constraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, ConstraintType type) {
        this(id, sourceMethod, sourceUnit, humanReadableCondition, type,
             humanReadableCondition, humanReadableCondition, humanReadableCondition);
    }
    
    public Constraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, ConstraintType type,
            String format1, String format2, String format3) {
        this.id = id;
        this.sourceMethod = sourceMethod;
        this.sourceUnit = sourceUnit;
        this.humanReadableCondition = humanReadableCondition;
        this.type = type;
        this.format1 = format1 != null ? format1 : humanReadableCondition;
        this.format2 = format2 != null ? format2 : humanReadableCondition;
        this.format3 = format3 != null ? format3 : humanReadableCondition;
    }

    public abstract boolean isCompatibleWith(Constraint other);

    public abstract String getConditionExpression();

    // New: Three-format getters
    public String getFormat1() {
        return format1;
    }

    public String getFormat2() {
        return format2;
    }

    public String getFormat3() {
        return format3;
    }

    // Getters
    public String getId() {
        return id;
    }

    public SootMethod getSourceMethod() {
        return sourceMethod;
    }

    public Unit getSourceUnit() {
        return sourceUnit;
    }

    public String getHumanReadableCondition() {
        return humanReadableCondition;
    }

    public ConstraintType getType() {
        return type;
    }

    @Override
    public String toString() {
        return String.format("%s: %s (in %s)",
                type, humanReadableCondition, sourceMethod.getName());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        Constraint that = (Constraint) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

/**
 * Represents an IF condition constraint (true/false branch)
 */
class ConditionalConstraint extends Constraint {
    private final boolean takeTrueBranch;
    private final String conditionVariable;
    private final String operator;
    private final String compareValue;

    public ConditionalConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, boolean takeTrueBranch,
            String conditionVariable, String operator, String compareValue) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.CONDITIONAL);
        this.takeTrueBranch = takeTrueBranch;
        this.conditionVariable = conditionVariable;
        this.operator = operator;
        this.compareValue = compareValue;
    }
    
    public ConditionalConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, boolean takeTrueBranch,
            String conditionVariable, String operator, String compareValue,
            String format1, String format2, String format3) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.CONDITIONAL,
              format1, format2, format3);
        this.takeTrueBranch = takeTrueBranch;
        this.conditionVariable = conditionVariable;
        this.operator = operator;
        this.compareValue = compareValue;
    }

    @Override
    public boolean isCompatibleWith(Constraint other) {
        if (!(other instanceof ConditionalConstraint))
            return true;

        ConditionalConstraint otherCond = (ConditionalConstraint) other;

        // Check for direct contradiction on same variable
        if (conditionVariable.equals(otherCond.conditionVariable) &&
                operator.equals(otherCond.operator) &&
                compareValue.equals(otherCond.compareValue)) {
            return takeTrueBranch == otherCond.takeTrueBranch;
        }

        // TODO: Add more sophisticated compatibility checking
        return true;
    }

    @Override
    public String getConditionExpression() {
        return takeTrueBranch ? format1 : "!(" + format1 + ")";
    }

    // Getters
    public boolean takeTrueBranch() {
        return takeTrueBranch;
    }

    public String getConditionVariable() {
        return conditionVariable;
    }

    public String getOperator() {
        return operator;
    }

    public String getCompareValue() {
        return compareValue;
    }
}

/**
 * Represents a SWITCH statement constraint (specific case taken)
 */
class SwitchConstraint extends Constraint {
    private final String switchVariable;
    private final String caseValue;
    private final boolean isDefaultCase;

    public SwitchConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, String switchVariable,
            String caseValue, boolean isDefaultCase) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.SWITCH);
        this.switchVariable = switchVariable;
        this.caseValue = caseValue;
        this.isDefaultCase = isDefaultCase;
    }
    
    public SwitchConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, String switchVariable,
            String caseValue, boolean isDefaultCase,
            String format1, String format2, String format3) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.SWITCH,
              format1, format2, format3);
        this.switchVariable = switchVariable;
        this.caseValue = caseValue;
        this.isDefaultCase = isDefaultCase;
    }

    @Override
    public boolean isCompatibleWith(Constraint other) {
        if (!(other instanceof SwitchConstraint))
            return true;

        SwitchConstraint otherSwitch = (SwitchConstraint) other;

        // Same switch variable can't have different case values
        if (switchVariable.equals(otherSwitch.switchVariable)) {
            return caseValue.equals(otherSwitch.caseValue);
        }

        return true;
    }

    @Override
    public String getConditionExpression() {
        return format1;
    }

    // Getters
    public String getSwitchVariable() {
        return switchVariable;
    }

    public String getCaseValue() {
        return caseValue;
    }

    public boolean isDefaultCase() {
        return isDefaultCase;
    }
}

/**
 * Represents method parameter constraints (required parameter values)
 */
class ParameterConstraint extends Constraint {
    private final int parameterIndex;
    private final String parameterName;
    private final String requiredValue;
    private final String parameterType;

    public ParameterConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, int parameterIndex,
            String parameterName, String requiredValue, String parameterType) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.PARAMETER);
        this.parameterIndex = parameterIndex;
        this.parameterName = parameterName;
        this.requiredValue = requiredValue;
        this.parameterType = parameterType;
    }
    
    public ParameterConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, int parameterIndex,
            String parameterName, String requiredValue, String parameterType,
            String format1, String format2, String format3) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.PARAMETER,
              format1, format2, format3);
        this.parameterIndex = parameterIndex;
        this.parameterName = parameterName;
        this.requiredValue = requiredValue;
        this.parameterType = parameterType;
    }

    @Override
    public boolean isCompatibleWith(Constraint other) {
        if (!(other instanceof ParameterConstraint))
            return true;

        ParameterConstraint otherParam = (ParameterConstraint) other;

        // Same parameter can't have different required values
        if (sourceMethod.equals(otherParam.sourceMethod) &&
                parameterIndex == otherParam.parameterIndex) {
            return requiredValue.equals(otherParam.requiredValue);
        }

        return true;
    }

    @Override
    public String getConditionExpression() {
        return format1;
    }

    // Getters
    public int getParameterIndex() {
        return parameterIndex;
    }

    public String getParameterName() {
        return parameterName;
    }

    public String getRequiredValue() {
        return requiredValue;
    }

    public String getParameterType() {
        return parameterType;
    }
}

/**
 * Represents field state constraints (object field values)
 */
class FieldConstraint extends Constraint {
    private final String fieldName;
    private final String objectName;
    private final String requiredValue;
    private final String fieldType;

    public FieldConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, String fieldName,
            String objectName, String requiredValue, String fieldType) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.FIELD);
        this.fieldName = fieldName;
        this.objectName = objectName;
        this.requiredValue = requiredValue;
        this.fieldType = fieldType;
    }
    
    public FieldConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, String fieldName,
            String objectName, String requiredValue, String fieldType,
            String format1, String format2, String format3) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.FIELD,
              format1, format2, format3);
        this.fieldName = fieldName;
        this.objectName = objectName;
        this.requiredValue = requiredValue;
        this.fieldType = fieldType;
    }

    @Override
    public boolean isCompatibleWith(Constraint other) {
        if (!(other instanceof FieldConstraint))
            return true;

        FieldConstraint otherField = (FieldConstraint) other;

        // Same field can't have different required values
        if (fieldName.equals(otherField.fieldName) &&
                objectName.equals(otherField.objectName)) {
            return requiredValue.equals(otherField.requiredValue);
        }

        return true;
    }

    @Override
    public String getConditionExpression() {
        return format1;
    }

    // Getters
    public String getFieldName() {
        return fieldName;
    }

    public String getObjectName() {
        return objectName;
    }

    public String getRequiredValue() {
        return requiredValue;
    }

    public String getFieldType() {
        return fieldType;
    }
}

/**
 * Represents Android-specific constraints (lifecycle, permissions, etc.)
 */
class AndroidConstraint extends Constraint {
    private final AndroidConstraintSubType subType;
    private final String componentName;
    private final Map<String, String> properties;

    public AndroidConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, AndroidConstraintSubType subType,
            String componentName, Map<String, String> properties) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.ANDROID);
        this.subType = subType;
        this.componentName = componentName;
        this.properties = new HashMap<>(properties);
    }
    
    public AndroidConstraint(String id, SootMethod sourceMethod, Unit sourceUnit,
            String humanReadableCondition, AndroidConstraintSubType subType,
            String componentName, Map<String, String> properties,
            String format1, String format2, String format3) {
        super(id, sourceMethod, sourceUnit, humanReadableCondition, ConstraintType.ANDROID,
              format1, format2, format3);
        this.subType = subType;
        this.componentName = componentName;
        this.properties = new HashMap<>(properties);
    }

    @Override
    public boolean isCompatibleWith(Constraint other) {
        if (!(other instanceof AndroidConstraint))
            return true;

        AndroidConstraint otherAndroid = (AndroidConstraint) other;

        // Check for conflicting Android constraints
        if (subType == otherAndroid.subType &&
                componentName.equals(otherAndroid.componentName)) {
            // Same constraint type and component should be compatible
            return true;
        }

        return true;
    }

    @Override
    public String getConditionExpression() {
        return format1;
    }

    // Getters
    public AndroidConstraintSubType getSubType() {
        return subType;
    }

    public String getComponentName() {
        return componentName;
    }

    public Map<String, String> getProperties() {
        return Collections.unmodifiableMap(properties);
    }
}

/**
 * Enumeration of constraint types
 */
enum ConstraintType {
    CONDITIONAL, // IF condition (true/false branch)
    SWITCH, // Switch case condition
    PARAMETER, // Method parameter constraint
    FIELD, // Object field constraint
    ANDROID // Android-specific constraint
}

/**
 * Enumeration of Android-specific constraint subtypes
 */
enum AndroidConstraintSubType {
    LIFECYCLE, // Activity/Service lifecycle state
    PERMISSION, // Required permission
    INTENT_EXTRA, // Intent extra value
    BUNDLE_EXTRA, // Bundle parameter value
    PREFERENCE, // SharedPreferences value
    SYSTEM_STATE // System state requirement
}