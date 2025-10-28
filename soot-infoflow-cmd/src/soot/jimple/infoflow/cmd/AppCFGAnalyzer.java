package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;

/**
 * Simple app CFG analyzer
 */
public class AppCFGAnalyzer {

    private final String appPackageName;
    private final AppMethodDiscovery discovery;
    private final BlockCFGExtractor extractor;

    public AppCFGAnalyzer(String appPackageName) {
        this.appPackageName = appPackageName;
        this.discovery = new AppMethodDiscovery(appPackageName);
        this.extractor = new BlockCFGExtractor();
    }

    /**
     * Run analysis and print all CFGs
     */
    public void analyze() {
        System.out.println("=== App CFG Analysis for: " + appPackageName + " ===\n");

        Set<SootMethod> methods = discovery.getAppMethods();

        for (SootMethod method : methods) {
            BlockCFGExtractor.MethodCFG cfg = extractor.extractCFG(method);
            if (cfg != null) {
                cfg.print();
            }
        }
    }

    /**
     * Print CFG for specific method name
     */
    public void printMethod(String methodName) {
        Set<SootMethod> methods = discovery.getAppMethods();

        for (SootMethod method : methods) {
            if (method.getName().equals(methodName)) {
                BlockCFGExtractor.MethodCFG cfg = extractor.extractCFG(method);
                if (cfg != null) {
                    cfg.print();
                }
            }
        }
    }
}