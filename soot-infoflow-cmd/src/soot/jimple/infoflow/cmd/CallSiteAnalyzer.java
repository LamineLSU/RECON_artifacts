package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import java.util.*;

/**
 * Analyzes method call sites within blocks and their continuation points
 * App-agnostic analyzer that works with any application package
 */
public class CallSiteAnalyzer {
    
    private final String appPackageName;
    private final Map<String, List<CallSite>> blockCallSites;
    private final Map<String, CallSiteInfo> callSiteDetails;
    
    public CallSiteAnalyzer(String appPackageName) {
        this.appPackageName = appPackageName;
        this.blockCallSites = new HashMap<>();
        this.callSiteDetails = new HashMap<>();
    }
    
    /**
     * Analyze all call sites in the app-level CFG
     */
    public void analyzeCallSites(Map<String, AppLevelCFGBuilder.AppCFGNode> appCFGNodes) {
        System.out.println("Analyzing call sites...");
        
        blockCallSites.clear();
        callSiteDetails.clear();
        
        for (AppLevelCFGBuilder.AppCFGNode node : appCFGNodes.values()) {
            analyzeBlockCallSites(node);
        }
        
        System.out.println("Found call sites in " + blockCallSites.size() + " blocks");
    }
    
    /**
     * Analyze call sites within a specific block
     */
    private void analyzeBlockCallSites(AppLevelCFGBuilder.AppCFGNode node) {
        List<CallSite> callSites = new ArrayList<>();
        List<Unit> units = node.block.units;
        
        for (int i = 0; i < units.size(); i++) {
            Unit unit = units.get(i);
            
            if (isMethodCall(unit)) {
                InvokeExpr invokeExpr = extractInvokeExpr(unit);
                if (invokeExpr != null) {
                    SootMethod targetMethod = invokeExpr.getMethod();
                    
                    if (isAppMethod(targetMethod)) {
                        CallSite callSite = new CallSite(
                            unit,
                            invokeExpr,
                            targetMethod,
                            i,
                            node.method
                        );
                        
                        callSites.add(callSite);
                        
                        // Analyze call site details
                        analyzeCallSiteDetails(node, callSite, i);
                    }
                }
            }
        }
        
        if (!callSites.isEmpty()) {
            blockCallSites.put(node.nodeId, callSites);
        }
    }
    
    /**
     * Analyze detailed information about a call site
     */
    private void analyzeCallSiteDetails(AppLevelCFGBuilder.AppCFGNode callerNode, CallSite callSite, int unitIndex) {
        String callSiteId = generateCallSiteId(callerNode.nodeId, unitIndex);
        
        // Determine continuation point
        String continuationPoint = determineContinuationPoint(callerNode, unitIndex);
        
        // Determine if this is the last call in the block
        boolean isLastInBlock = (unitIndex == callerNode.block.units.size() - 1);
        
        // Check if there are statements after the call
        boolean hasPostCallStatements = (unitIndex < callerNode.block.units.size() - 1);
        
        CallSiteInfo info = new CallSiteInfo(
            callSiteId,
            callerNode.nodeId,
            callSite.targetMethod,
            continuationPoint,
            isLastInBlock,
            hasPostCallStatements,
            unitIndex
        );
        
        callSiteDetails.put(callSiteId, info);
    }
    
    /**
     * Determine where execution continues after method call returns
     */
    private String determineContinuationPoint(AppLevelCFGBuilder.AppCFGNode callerNode, int callUnitIndex) {
        // If call is not the last unit in block, continuation is same block
        if (callUnitIndex < callerNode.block.units.size() - 1) {
            return callerNode.nodeId; // Continue in same block
        }
        
        // If call is last unit, continuation is successor blocks
        if (!callerNode.block.successors.isEmpty()) {
            // For simplicity, return first successor
            // In practice, all successors should be valid continuation points
            Integer firstSuccessor = callerNode.block.successors.iterator().next();
            return callerNode.method.getSignature() + "_block_" + firstSuccessor;
        }
        
        return null; // No continuation (method ends)
    }
    
    /**
     * Check if unit contains a method call
     */
    private boolean isMethodCall(Unit unit) {
        if (unit instanceof InvokeStmt) {
            return true;
        }
        if (unit instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) unit;
            return assign.getRightOp() instanceof InvokeExpr;
        }
        return false;
    }
    
    /**
     * Extract InvokeExpr from unit
     */
    private InvokeExpr extractInvokeExpr(Unit unit) {
        if (unit instanceof InvokeStmt) {
            return ((InvokeStmt) unit).getInvokeExpr();
        }
        if (unit instanceof AssignStmt) {
            AssignStmt assign = (AssignStmt) unit;
            if (assign.getRightOp() instanceof InvokeExpr) {
                return (InvokeExpr) assign.getRightOp();
            }
        }
        return null;
    }
    
    /**
     * Check if method belongs to app package (app-agnostic)
     */
    private boolean isAppMethod(SootMethod method) {
        return method.getDeclaringClass().getPackageName().startsWith(appPackageName);
    }
    
    /**
     * Generate unique call site identifier
     */
    private String generateCallSiteId(String blockId, int unitIndex) {
        return blockId + "_call_" + unitIndex;
    }
    
    /**
     * Get call sites for a specific block
     */
    public List<CallSite> getCallSitesForBlock(String blockId) {
        return blockCallSites.getOrDefault(blockId, new ArrayList<>());
    }
    
    /**
     * Get call site details
     */
    public CallSiteInfo getCallSiteInfo(String callSiteId) {
        return callSiteDetails.get(callSiteId);
    }
    
    /**
     * Get all blocks that contain method calls
     */
    public Set<String> getBlocksWithCallSites() {
        return Collections.unmodifiableSet(blockCallSites.keySet());
    }
    
    /**
     * Check if block contains any method calls
     */
    public boolean hasCallSites(String blockId) {
        return blockCallSites.containsKey(blockId) && !blockCallSites.get(blockId).isEmpty();
    }
    
    /**
     * Get total number of call sites
     */
    public int getTotalCallSites() {
        return blockCallSites.values().stream().mapToInt(List::size).sum();
    }
    
    /**
     * Print call site analysis summary
     */
    public void printCallSiteSummary() {
        System.out.println("\n=== Call Site Analysis Summary ===");
        System.out.println("Blocks with call sites: " + blockCallSites.size());
        System.out.println("Total call sites: " + getTotalCallSites());
        
        for (Map.Entry<String, List<CallSite>> entry : blockCallSites.entrySet()) {
            String blockId = entry.getKey();
            List<CallSite> callSites = entry.getValue();
            
            String blockName = extractBlockName(blockId);
            System.out.println("\n" + blockName + " (" + callSites.size() + " calls):");
            
            for (CallSite callSite : callSites) {
                String callSiteId = generateCallSiteId(blockId, callSite.unitIndex);
                CallSiteInfo info = callSiteDetails.get(callSiteId);
                
                System.out.println("  -> " + callSite.targetMethod.getName() + 
                                 " (continuation: " + extractBlockName(info.continuationPoint) + ")");
            }
        }
    }
    
    /**
     * Extract readable block name from block ID
     */
    private String extractBlockName(String blockId) {
        if (blockId == null) return "null";
        
        if (blockId.contains("_block_")) {
            String[] parts = blockId.split("_block_");
            if (parts.length == 2) {
                String signature = parts[0];
                String blockIndex = parts[1];
                String methodName = extractMethodName(signature);
                return methodName + "_block_" + blockIndex;
            }
        }
        return blockId;
    }
    
    /**
     * Extract method name from signature
     */
    private String extractMethodName(String signature) {
        if (signature.contains(": ") && signature.contains(" ")) {
            String[] parts = signature.split(": ");
            if (parts.length >= 2) {
                String methodPart = parts[1];
                String[] methodParts = methodPart.split(" ");
                if (methodParts.length >= 2) {
                    String methodWithParams = methodParts[1];
                    if (methodWithParams.contains("(")) {
                        return methodWithParams.substring(0, methodWithParams.indexOf("("));
                    }
                    return methodWithParams;
                }
            }
        }
        return signature;
    }
    
    /**
     * Represents a method call site
     */
    public static class CallSite {
        public final Unit unit;
        public final InvokeExpr invokeExpr;
        public final SootMethod targetMethod;
        public final int unitIndex;
        public final SootMethod callerMethod;
        
        public CallSite(Unit unit, InvokeExpr invokeExpr, SootMethod targetMethod, 
                       int unitIndex, SootMethod callerMethod) {
            this.unit = unit;
            this.invokeExpr = invokeExpr;
            this.targetMethod = targetMethod;
            this.unitIndex = unitIndex;
            this.callerMethod = callerMethod;
        }
        
        @Override
        public String toString() {
            return callerMethod.getName() + " calls " + targetMethod.getName() + " at unit " + unitIndex;
        }
    }
    
    /**
     * Detailed information about a call site
     */
    public static class CallSiteInfo {
        public final String callSiteId;
        public final String callerBlockId;
        public final SootMethod targetMethod;
        public final String continuationPoint;
        public final boolean isLastInBlock;
        public final boolean hasPostCallStatements;
        public final int unitIndex;
        
        public CallSiteInfo(String callSiteId, String callerBlockId, SootMethod targetMethod,
                           String continuationPoint, boolean isLastInBlock, boolean hasPostCallStatements,
                           int unitIndex) {
            this.callSiteId = callSiteId;
            this.callerBlockId = callerBlockId;
            this.targetMethod = targetMethod;
            this.continuationPoint = continuationPoint;
            this.isLastInBlock = isLastInBlock;
            this.hasPostCallStatements = hasPostCallStatements;
            this.unitIndex = unitIndex;
        }
        
        @Override
        public String toString() {
            return callSiteId + " -> " + targetMethod.getName() + 
                   " (continues at: " + continuationPoint + ")";
        }
    }
}