package soot.jimple.infoflow.cmd;

import soot.SootMethod;
import soot.Unit;
import soot.toolkits.graph.UnitGraph;
import soot.jimple.Stmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.AssignStmt;
import java.util.*;

/**
 * Stores CFG information for a single method that can reach the sink.
 * Contains the method, its unit-level CFG, and metadata for constraint
 * extraction.
 */
public class MethodCFGInfo {

    private SootMethod method;
    private UnitGraph cfg;
    private Set<Unit> sinkLeadingCalls; // Statements that call toward sink
    private Map<Unit, BranchCondition> branchConditions; // Branch conditions extracted
    private boolean analyzed; // Whether this CFG has been analyzed for sink paths

    public MethodCFGInfo(SootMethod method, UnitGraph cfg) {
        this.method = method;
        this.cfg = cfg;
        this.sinkLeadingCalls = new HashSet<>();
        this.branchConditions = new HashMap<>();
        this.analyzed = false;
    }

    /**
     * Get the method this CFG represents
     */
    public SootMethod getMethod() {
        return method;
    }

    /**
     * Get the unit-level CFG
     */
    public UnitGraph getCFG() {
        return cfg;
    }

    /**
     * Get all units (statements) in this method
     */
    public Collection<Unit> getUnits() {
        return cfg.getBody().getUnits();
    }

    /**
     * Get all units that call methods toward the sink
     */
    public Set<Unit> getSinkLeadingCalls() {
        return Collections.unmodifiableSet(sinkLeadingCalls);
    }

    /**
     * Add a unit as a sink-leading call site
     */
    public void addSinkLeadingCall(Unit callSite) {
        sinkLeadingCalls.add(callSite);
    }

    /**
     * Check if a unit contains a method call
     */
    public boolean isMethodCall(Unit unit) {
        if (!(unit instanceof Stmt))
            return false;

        Stmt stmt = (Stmt) unit;

        // Check for invoke statements
        if (stmt instanceof InvokeStmt) {
            return true;
        }

        // Check for assignment with invoke expression
        if (stmt instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) stmt;
            return assign.getRightOp() instanceof InvokeExpr;
        }

        return false;
    }

    /**
     * Get the method being called at a call site (if any)
     */
    public SootMethod getCalledMethod(Unit callSite) {
        if (!isMethodCall(callSite))
            return null;

        Stmt stmt = (Stmt) callSite;
        InvokeExpr invokeExpr = null;

        if (stmt instanceof InvokeStmt) {
            invokeExpr = ((InvokeStmt) stmt).getInvokeExpr();
        } else if (stmt instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) stmt;
            if (assign.getRightOp() instanceof InvokeExpr) {
                invokeExpr = (InvokeExpr) assign.getRightOp();
            }
        }

        return invokeExpr != null ? invokeExpr.getMethod() : null;
    }

    /**
     * Get successors of a unit in the CFG
     */
    public List<Unit> getSuccessors(Unit unit) {
        return cfg.getSuccsOf(unit);
    }

    /**
     * Get predecessors of a unit in the CFG
     */
    public List<Unit> getPredecessors(Unit unit) {
        return cfg.getPredsOf(unit);
    }

    /**
     * Get the entry point(s) of this method's CFG
     */
    public List<Unit> getEntryPoints() {
        return cfg.getHeads();
    }

    /**
     * Get the exit point(s) of this method's CFG
     */
    public List<Unit> getExitPoints() {
        return cfg.getTails();
    }

    /**
     * Add a branch condition for a conditional statement
     */
    public void addBranchCondition(Unit branchUnit, BranchCondition condition) {
        branchConditions.put(branchUnit, condition);
    }

    /**
     * Get branch condition for a unit (if it's a conditional)
     */
    public BranchCondition getBranchCondition(Unit unit) {
        return branchConditions.get(unit);
    }

    /**
     * Get all branch conditions in this method
     */
    public Map<Unit, BranchCondition> getAllBranchConditions() {
        return Collections.unmodifiableMap(branchConditions);
    }

    /**
     * Mark this CFG as analyzed for sink paths
     */
    public void setAnalyzed(boolean analyzed) {
        this.analyzed = analyzed;
    }

    /**
     * Check if this CFG has been analyzed for sink paths
     */
    public boolean isAnalyzed() {
        return analyzed;
    }

    /**
     * Get statistics about this CFG
     */
    public CFGStatistics getStatistics() {
        int totalUnits = getUnits().size();
        int callSites = 0;
        int branchPoints = 0;

        for (Unit unit : getUnits()) {
            if (isMethodCall(unit)) {
                callSites++;
            }
            if (getSuccessors(unit).size() > 1) {
                branchPoints++;
            }
        }

        return new CFGStatistics(totalUnits, callSites, branchPoints, sinkLeadingCalls.size());
    }

    @Override
    public String toString() {
        CFGStatistics stats = getStatistics();
        return String.format("MethodCFG{%s, units=%d, calls=%d, branches=%d, sinkCalls=%d}",
                method.getName(), stats.totalUnits, stats.callSites,
                stats.branchPoints, stats.sinkLeadingCalls);
    }

    /**
     * Helper class to store CFG statistics
     */
    public static class CFGStatistics {
        public final int totalUnits;
        public final int callSites;
        public final int branchPoints;
        public final int sinkLeadingCalls;

        public CFGStatistics(int totalUnits, int callSites, int branchPoints, int sinkLeadingCalls) {
            this.totalUnits = totalUnits;
            this.callSites = callSites;
            this.branchPoints = branchPoints;
            this.sinkLeadingCalls = sinkLeadingCalls;
        }
    }

    /**
     * Helper class to store branch condition information
     */
    public static class BranchCondition {
        private Unit conditionUnit;
        private String condition; // The textual condition (e.g., "$i0 != $i1")
        private Unit trueBranch;
        private Unit falseBranch;

        public BranchCondition(Unit conditionUnit, String condition, Unit trueBranch, Unit falseBranch) {
            this.conditionUnit = conditionUnit;
            this.condition = condition;
            this.trueBranch = trueBranch;
            this.falseBranch = falseBranch;
        }

        public Unit getConditionUnit() {
            return conditionUnit;
        }

        public String getCondition() {
            return condition;
        }

        public Unit getTrueBranch() {
            return trueBranch;
        }

        public Unit getFalseBranch() {
            return falseBranch;
        }

        @Override
        public String toString() {
            return String.format("BranchCondition{%s, true->%s, false->%s}",
                    condition,
                    trueBranch != null
                            ? trueBranch.toString().substring(0, Math.min(20, trueBranch.toString().length()))
                            : "null",
                    falseBranch != null
                            ? falseBranch.toString().substring(0, Math.min(20, falseBranch.toString().length()))
                            : "null");
        }
    }
}