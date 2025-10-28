package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;

/**
 * Enumerates all internal paths within individual methods
 * Provides path templates for composite path construction
 */
public class MethodPathEnumerator {

    private final Map<SootMethod, List<MethodPath>> methodPathCache;

    public MethodPathEnumerator() {
        this.methodPathCache = new HashMap<>();
    }

    /**
     * Get all internal paths for a method (cached)
     */
    public List<MethodPath> getMethodPaths(SootMethod method, BlockCFGExtractor.MethodCFG methodCFG) {
        if (methodPathCache.containsKey(method)) {
            return methodPathCache.get(method);
        }

        List<MethodPath> paths = enumerateInternalPaths(method, methodCFG);
        methodPathCache.put(method, paths);
        return paths;
    }

    /**
     * Enumerate all paths from entry to exit within a single method
     */
    private List<MethodPath> enumerateInternalPaths(SootMethod method, BlockCFGExtractor.MethodCFG methodCFG) {
        List<MethodPath> allPaths = new ArrayList<>();

        if (methodCFG.getEntryBlocks().isEmpty()) {
            return allPaths;
        }

        // Start DFS from each entry block
        for (BlockCFGExtractor.CFGBlock entryBlock : methodCFG.getEntryBlocks()) {
            List<String> currentPath = new ArrayList<>();
            Set<String> visitedInPath = new HashSet<>();

            String entryBlockId = getBlockId(method, entryBlock.sootIndex);
            dfsInternalPaths(entryBlockId, method, methodCFG, currentPath, visitedInPath, allPaths);
        }

        System.out.println("Method " + method.getName() + " has " + allPaths.size() + " internal paths");
        return allPaths;
    }

    /**
     * DFS to find all internal paths within method boundaries
     */
    private void dfsInternalPaths(String currentBlockId, SootMethod method, BlockCFGExtractor.MethodCFG methodCFG,
            List<String> currentPath, Set<String> visitedInPath, List<MethodPath> allPaths) {

        // Add current block to path
        currentPath.add(currentBlockId);
        visitedInPath.add(currentBlockId);

        // Find the CFG block
        BlockCFGExtractor.CFGBlock currentBlock = findBlockById(methodCFG, currentBlockId);
        if (currentBlock == null) {
            currentPath.remove(currentPath.size() - 1);
            visitedInPath.remove(currentBlockId);
            return;
        }

        // Check if this is an exit block
        if (isExitBlock(currentBlock, methodCFG)) {
            // Found a complete internal path
            MethodPath methodPath = new MethodPath(method, new ArrayList<>(currentPath));
            allPaths.add(methodPath);
        } else {
            // Continue to successor blocks within same method
            for (Integer successorIndex : currentBlock.successors) {
                String successorBlockId = getBlockId(method, successorIndex);

                if (!visitedInPath.contains(successorBlockId)) {
                    dfsInternalPaths(successorBlockId, method, methodCFG, currentPath, visitedInPath, allPaths);
                }
            }
        }

        // Backtrack
        currentPath.remove(currentPath.size() - 1);
        visitedInPath.remove(currentBlockId);
    }

    /**
     * Find CFG block by block ID
     */
    private BlockCFGExtractor.CFGBlock findBlockById(BlockCFGExtractor.MethodCFG methodCFG, String blockId) {
        // Extract block index from blockId (format: methodSignature_block_index)
        int blockIndex = extractBlockIndex(blockId);

        for (BlockCFGExtractor.CFGBlock block : methodCFG.blocks) {
            if (block.sootIndex == blockIndex) {
                return block;
            }
        }
        return null;
    }

    /**
     * Check if block is an exit block
     */
    private boolean isExitBlock(BlockCFGExtractor.CFGBlock block, BlockCFGExtractor.MethodCFG methodCFG) {
        for (BlockCFGExtractor.CFGBlock exitBlock : methodCFG.getExitBlocks()) {
            if (exitBlock.sootIndex == block.sootIndex) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate block ID
     */
    private String getBlockId(SootMethod method, int blockIndex) {
        return method.getSignature() + "_block_" + blockIndex;
    }

    /**
     * Extract block index from block ID
     */
    private int extractBlockIndex(String blockId) {
        String[] parts = blockId.split("_block_");
        if (parts.length == 2) {
            return Integer.parseInt(parts[1]);
        }
        return -1;
    }

    /**
     * Represents a single path through a method
     */
    public static class MethodPath {
        public final SootMethod method;
        public final List<String> blockSequence;

        public MethodPath(SootMethod method, List<String> blockSequence) {
            this.method = method;
            this.blockSequence = new ArrayList<>(blockSequence);
        }

        /**
         * Get the entry block of this path
         */
        public String getEntryBlock() {
            return blockSequence.isEmpty() ? null : blockSequence.get(0);
        }

        /**
         * Get the exit block of this path
         */
        public String getExitBlock() {
            return blockSequence.isEmpty() ? null : blockSequence.get(blockSequence.size() - 1);
        }

        /**
         * Get path length
         */
        public int getLength() {
            return blockSequence.size();
        }

        /**
         * Check if this path contains a specific block
         */
        public boolean containsBlock(String blockId) {
            return blockSequence.contains(blockId);
        }

        /**
         * Get readable path summary
         */
        public String getPathSummary() {
            if (blockSequence.isEmpty()) {
                return "Empty path";
            }

            String methodName = method.getName();
            int entryIndex = extractBlockIndex(getEntryBlock());
            int exitIndex = extractBlockIndex(getExitBlock());

            return methodName + ": block_" + entryIndex + " -> block_" + exitIndex +
                    " (" + blockSequence.size() + " blocks)";
        }

        /**
         * Extract block index from block ID
         */
        private int extractBlockIndex(String blockId) {
            if (blockId == null)
                return -1;
            String[] parts = blockId.split("_block_");
            if (parts.length == 2) {
                return Integer.parseInt(parts[1]);
            }
            return -1;
        }

        @Override
        public String toString() {
            return getPathSummary();
        }
    }

    /**
     * Clear cache (for testing)
     */
    public void clearCache() {
        methodPathCache.clear();
    }

    /**
     * Get cache statistics
     */
    public void printCacheStats() {
        System.out.println("Method path cache contains " + methodPathCache.size() + " methods:");
        for (Map.Entry<SootMethod, List<MethodPath>> entry : methodPathCache.entrySet()) {
            System.out.println("  " + entry.getKey().getName() + ": " + entry.getValue().size() + " paths");
        }
    }
}