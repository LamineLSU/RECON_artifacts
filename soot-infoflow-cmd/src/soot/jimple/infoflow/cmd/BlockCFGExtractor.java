package soot.jimple.infoflow.cmd;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Simple block-level CFG extractor
 */
public class BlockCFGExtractor {
    
    /**
     * Extract block CFG for a method
     */
    public MethodCFG extractCFG(SootMethod method) {
        if (!method.hasActiveBody()) {
            return null;
        }
        
        ExceptionalBlockGraph blockGraph = new ExceptionalBlockGraph(method.getActiveBody());
        
        List<CFGBlock> blocks = new ArrayList<>();
        Map<Block, CFGBlock> blockMap = new HashMap<>();
        
        // Create blocks
        for (Block block : blockGraph) {
            List<Unit> units = new ArrayList<>();
            for (Unit unit : block) {
                units.add(unit);
            }
            CFGBlock cfgBlock = new CFGBlock(block.getIndexInMethod(), units);
            blocks.add(cfgBlock);
            blockMap.put(block, cfgBlock);
        }
        
        // Connect blocks
        for (Block block : blockGraph) {
            CFGBlock cfgBlock = blockMap.get(block);
            for (Block succ : blockGraph.getSuccsOf(block)) {
                cfgBlock.successors.add(succ.getIndexInMethod());
            }
        }
        
        // Find entry and exit blocks
        List<CFGBlock> entryBlocks = new ArrayList<>();
        List<CFGBlock> exitBlocks = new ArrayList<>();
        
        for (Block head : blockGraph.getHeads()) {
            entryBlocks.add(blockMap.get(head));
        }
        
        for (Block tail : blockGraph.getTails()) {
            exitBlocks.add(blockMap.get(tail));
        }
        
        return new MethodCFG(method, blocks, entryBlocks, exitBlocks);
    }
    
    /**
     * Simple block representation
     */
    public static class CFGBlock {
        public final int sootIndex;
        public final Set<Integer> successors;
        public final List<Unit> units;
        
        public CFGBlock(int sootIndex, List<Unit> units) {
            this.sootIndex = sootIndex;
            this.successors = new HashSet<>();
            this.units = new ArrayList<>(units);
        }
        
        /**
         * Get statements as strings for display
         */
        public List<String> getStatements() {
            return units.stream()
                       .map(Unit::toString)
                       .collect(Collectors.toList());
        }
    }
    
    /**
     * Method CFG representation
     */
    public static class MethodCFG {
        public final SootMethod method;
        public final List<CFGBlock> blocks;
        private final List<CFGBlock> entryBlocks;
        private final List<CFGBlock> exitBlocks;
        
        public MethodCFG(SootMethod method, List<CFGBlock> blocks, 
                        List<CFGBlock> entryBlocks, List<CFGBlock> exitBlocks) {
            this.method = method;
            this.blocks = blocks;
            this.entryBlocks = entryBlocks;
            this.exitBlocks = exitBlocks;
        }
        
        /**
         * Get entry blocks
         */
        public List<CFGBlock> getEntryBlocks() {
            return Collections.unmodifiableList(entryBlocks);
        }
        
        /**
         * Get exit blocks
         */
        public List<CFGBlock> getExitBlocks() {
            return Collections.unmodifiableList(exitBlocks);
        }
        
        public int getBlockCount() {
            return blocks.size();
        }
        
        /**
         * Print the CFG
         */
        public void print() {
            System.out.println("=== CFG for " + method.getName() + " ===");
            System.out.println("Block count: " + blocks.size());
            
            for (CFGBlock block : blocks) {
                System.out.println("Block ID: " + block.sootIndex);
                System.out.println("Statements:");
                for (String stmt : block.getStatements()) {
                    System.out.println("  " + stmt);
                }
                System.out.print("Successor Block IDs: [");
                System.out.print(String.join(", ", block.successors.stream()
                    .map(String::valueOf).toArray(String[]::new)));
                System.out.println("]");
                System.out.println();
            }
        }
    }
}