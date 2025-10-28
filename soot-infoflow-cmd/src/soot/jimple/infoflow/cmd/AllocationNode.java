package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;

public class AllocationNode {
    private final String id;
    private final NodeType type;
    private final Unit unit;
    private final SootMethod method;
    private final Value value;
    private final Set<AllocationNode> successors;
    private final Set<AllocationNode> predecessors;
    private final Set<AllocationNode> childNodes;
    private final Set<String> tags;

    // For method calls and activity transitions
    private SootMethod targetMethod; // Called method or onCreate method
    private SootClass targetClass; // Target activity class
    private AllocationNode targetEntryNode; // Entry node of target graph
    private AllocationNode nextCFGNode; // Next node in caller's CFG

    public AllocationNode(String id, NodeType type, Unit unit, SootMethod method, Value value) {
        this.id = id;
        this.type = type;
        this.unit = unit;
        this.method = method;
        this.value = value;
        this.successors = new HashSet<>();
        this.predecessors = new HashSet<>();
        this.childNodes = new HashSet<>();
        this.tags = new HashSet<>();
    }

    public void setMethodCallTarget(SootMethod target, AllocationNode entryNode, AllocationNode nextInCFG) {
        this.targetMethod = target;
        this.targetEntryNode = entryNode;
        this.nextCFGNode = nextInCFG;

        // Connect to both entry of called method and next node in CFG
        if (entryNode != null) {
            addSuccessor(entryNode);
        }
        if (nextInCFG != null) {
            addSuccessor(nextInCFG);
        }
    }

    public void setActivityTransitionTarget(SootClass targetActivity, SootMethod onCreate, AllocationNode entryNode) {
        this.targetClass = targetActivity;
        this.targetMethod = onCreate;
        this.targetEntryNode = entryNode;

        // For activity transition, only connect to target's entry
        if (entryNode != null) {
            addSuccessor(entryNode);
        }
    }

    public void setThreadTarget(SootMethod runMethod, AllocationNode threadEntry, AllocationNode threadComplete) {
        this.targetMethod = runMethod;
        this.targetEntryNode = threadEntry;

        // Connect thread spawn to both entry and completion
        if (threadEntry != null) {
            addSuccessor(threadEntry);
        }
        if (threadComplete != null) {
            threadEntry.addSuccessor(threadComplete);
        }
    }

    public void addChild(AllocationNode child) {
        if (child != null) {
            childNodes.add(child);
            addSuccessor(child);
        }
    }

    public void addSuccessor(AllocationNode node) {
        if (node != null) {
            successors.add(node);
            node.addPredecessor(this);
        }
    }

    private void addPredecessor(AllocationNode node) {
        if (node != null) {
            predecessors.add(node);
        }
    }

    public boolean isAllocation() {
        return type == NodeType.ALLOCATION && value != null &&
                (value instanceof NewExpr ||
                        value instanceof NewArrayExpr ||
                        value instanceof NewMultiArrayExpr);
    }

    public boolean isMethodCall() {
        return type == NodeType.METHOD_CALL;
    }

    public boolean isControlFlow() {
        return type == NodeType.IF_CONDITION || type == NodeType.SWITCH;
    }

    public String getAllocationTypeName() {
        if (!isAllocation())
            return null;

        if (value instanceof NewExpr) {
            return ((NewExpr) value).getBaseType().toString();
        } else if (value instanceof NewArrayExpr) {
            return ((NewArrayExpr) value).getBaseType().toString() + "[]";
        } else if (value instanceof NewMultiArrayExpr) {
            return ((NewMultiArrayExpr) value).getBaseType().toString() + "[][]";
        }
        return null;
    }

    public InvokeExpr getMethodCall() {
        if (!isMethodCall() || unit == null)
            return null;

        if (unit instanceof InvokeStmt) {
            return ((InvokeStmt) unit).getInvokeExpr();
        } else if (unit instanceof AssignStmt) {
            Value rightOp = ((AssignStmt) unit).getRightOp();
            if (rightOp instanceof InvokeExpr) {
                return (InvokeExpr) rightOp;
            }
        }
        return null;
    }

    // Getters
    public String getId() {
        return id;
    }

    public NodeType getType() {
        return type;
    }

    public Unit getUnit() {
        return unit;
    }

    public Value getValue() {
        return value;
    }

    public SootMethod getMethod() {
        return method;
    }

    public Set<AllocationNode> getSuccessors() {
        return Collections.unmodifiableSet(successors);
    }

    public Set<AllocationNode> getPredecessors() {
        return Collections.unmodifiableSet(predecessors);
    }

    public Set<AllocationNode> getChildNodes() {
        return Collections.unmodifiableSet(childNodes);
    }

    public SootMethod getTargetMethod() {
        return targetMethod;
    }

    public SootClass getTargetClass() {
        return targetClass;
    }

    public AllocationNode getTargetEntryNode() {
        return targetEntryNode;
    }

    public AllocationNode getNextCFGNode() {
        return nextCFGNode;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Node[").append(type).append("]: ").append(id);

        if (method != null) {
            sb.append(" in ").append(method.getName());
        }

        if (isAllocation()) {
            sb.append(" (").append(getAllocationTypeName()).append(")");
        } else if (isMethodCall() && getMethodCall() != null) {
            sb.append(" (calls ").append(getMethodCall().getMethod().getName()).append(")");
        }

        if (targetClass != null) {
            sb.append(" -> ").append(targetClass.getName());
        }

        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        AllocationNode that = (AllocationNode) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}