package soot.jimple.infoflow.cmd;

public enum NodeType {
    ENTRY, // Method/Activity entry point
    EXIT, // Method exit point
    ALLOCATION, // Object allocation
    METHOD_CALL, // Method invocation
    THREAD_SPAWN, // Thread creation point
    THREAD_COMPLETE, // Thread completion point
    ACTIVITY_TRANSITION, // Activity transition point
    IF_CONDITION, // If statement
    SWITCH, // Switch statement
    CONTROL_MERGE
}