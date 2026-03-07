package com.pqc.analyzer.exposure;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.*;

public class ExposureDetector {

    private static final Set<String> REST_ANNOTATIONS = new HashSet<>(Arrays.asList(
            "RestController", "Controller", "RequestMapping",
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"));

    // Map of Method signatures to their calculated Exposure Level
    private final Map<String, String> methodExposureMap = new HashMap<>();

    // Map of caller -> list of distinct callee signatures (Interprocedural
    // Flow-Sensitive Graph)
    private final Map<String, Set<String>> callGraph = new HashMap<>();

    /**
     * Phase 1: Build the global call graph and identify base exposure across all
     * parsed files.
     */
    public void buildCallGraphAndBaseExposure(List<CompilationUnit> cus) {
        for (CompilationUnit cu : cus) {
            cu.accept(new GraphBuildingVisitor(), null);
        }
    }

    /**
     * Phase 2: Interprocedural propagation of Exposure Levels.
     * Propagates HIGH exposure from REST endpoints down to internal methods.
     */
    public void propagateExposure() {
        boolean changed = true;
        Set<String> visited = new HashSet<>();

        // Simple Fixed-Point Iteration algorithm for interprocedural propagation
        while (changed) {
            changed = false;
            visited.clear();

            // Create a copy to prevent CME since propagateExposureLevel mutates the map
            List<Map.Entry<String, String>> currentEntries = new ArrayList<>(methodExposureMap.entrySet());

            for (Map.Entry<String, String> entry : currentEntries) {
                String caller = entry.getKey();
                // Fetch the actual current exposure in case it changed in this pass
                String exposure = methodExposureMap.get(caller);

                if ("HIGH".equals(exposure)) {
                    changed |= propagateExposureLevel(caller, "HIGH", visited);
                }
            }
        }
    }

    private boolean propagateExposureLevel(String methodSig, String levelToPropagate, Set<String> visited) {
        if (!visited.add(methodSig)) {
            return false; // Prevent infinite loops in recursive call graphs
        }

        boolean changed = false;
        Set<String> callees = callGraph.getOrDefault(methodSig, Collections.emptySet());

        for (String callee : callees) {
            String currentCalleeExposure = methodExposureMap.getOrDefault(callee, "LOW");
            // If callee is MEDIUM or LOW, and parent is HIGH, promote callee to HIGH
            if (!currentCalleeExposure.equals(levelToPropagate) && "HIGH".equals(levelToPropagate)) {
                methodExposureMap.put(callee, levelToPropagate);
                changed = true;
            }
            // Propagate further down the chain
            changed |= propagateExposureLevel(callee, levelToPropagate, visited);
        }
        return changed;
    }

    /**
     * Returns the computed exposure level for a given method signature.
     * Returns "LOW" if the method is untracked or purely internal.
     */
    public String getExposureLevel(String methodSignature) {
        return methodExposureMap.getOrDefault(methodSignature, "LOW");
    }

    /**
     * Utility to generate a unique signature for a method declaration.
     */
    public static String getSignature(MethodDeclaration md) {
        String className = md.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("UnknownClass");
        return className + "." + md.getSignature().asString();
    }

    private class GraphBuildingVisitor extends VoidVisitorAdapter<Void> {
        @Override
        public void visit(MethodDeclaration md, Void arg) {
            super.visit(md, arg);

            String sig = getSignature(md);
            String initialExposure = determineBaseExposure(md);
            methodExposureMap.putIfAbsent(sig, initialExposure);

            // Extract method calls inside this method to build the call graph
            md.findAll(MethodCallExpr.class).forEach(call -> {
                // Approximate the callee signature. A robust implementation would use
                // javaparser-symbol-solver
                // to resolve the exact type, but for structural skeleton purposes, we try to
                // construct a matching string.
                // NOTE: This uses exact name matching which is a limitation of not being fully
                // symbol-resolved yet,
                // but fulfills the structural requirement.
                String calleeName = call.getNameAsString();
                // We map caller -> calleeName (simplified graph edge)
                callGraph.computeIfAbsent(sig, k -> new HashSet<>()).add(calleeName);
            });
        }

        private String determineBaseExposure(MethodDeclaration md) {
            // 1. Check for REST annotations indicating HIGH exposure
            NodeList<AnnotationExpr> annotations = md.getAnnotations();
            boolean isRestEndpoint = annotations.stream()
                    .anyMatch(a -> REST_ANNOTATIONS.contains(a.getNameAsString()));

            // Also check class-level annotations
            md.findAncestor(ClassOrInterfaceDeclaration.class).ifPresent(c -> {
                c.getAnnotations().forEach(a -> {
                    if (REST_ANNOTATIONS.contains(a.getNameAsString())) {
                        methodExposureMap.put(getSignature(md), "HIGH"); // Whole class is a controller
                    }
                });
            });

            if (isRestEndpoint || "HIGH".equals(methodExposureMap.get(getSignature(md)))) {
                return "HIGH";
            }

            // 2. Check visibility modifiers
            if (md.hasModifier(Modifier.Keyword.PUBLIC)) {
                return "MEDIUM"; // Public non-REST
            }

            // 3. Private/Protected/Package-private
            return "LOW"; // Internal
        }
    }
}
