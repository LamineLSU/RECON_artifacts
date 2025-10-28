package soot.jimple.infoflow.cmd;

import soot.*;
import java.util.*;

/**
 * Simple method discovery for app classes only
 */
public class AppMethodDiscovery {

    private final String appPackageName;

    public AppMethodDiscovery(String appPackageName) {
        this.appPackageName = appPackageName;
    }

    /**
     * Get all app methods with active bodies
     */
    public Set<SootMethod> getAppMethods() {
        Set<SootMethod> appMethods = new HashSet<>();

        for (SootClass cls : Scene.v().getApplicationClasses()) {
            if (cls.getPackageName().startsWith(appPackageName)) {
                for (SootMethod method : cls.getMethods()) {
                    if (method.hasActiveBody()) {
                        appMethods.add(method);
                    }
                }
            }
        }

        System.out.println("Found " + appMethods.size() + " app methods");
        return appMethods;
    }
}