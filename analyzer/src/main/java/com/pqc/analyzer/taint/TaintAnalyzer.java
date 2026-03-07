package com.pqc.analyzer.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.pqc.analyzer.exposure.ExposureDetector; // Reusing getSignature utility

import java.util.*;

import com.github.javaparser.ast.NodeList;

public class TaintAnalyzer {

    // Global sets bridging all parsed files
    // Maps Method Signature -> Indices of parameters that act as sinks in that
    // method
    private final Map<String, Set<Integer>> methodSinks = new HashMap<>();

    // Maps Method Signature -> Indices of parameters that are inherently tainted in
    // that method
    // (e.g., due to @RequestBody)
    private final Map<String, Set<Integer>> methodTaintedParams = new HashMap<>();

    // Record of globally identified tainted sinking calls (MethodCallExpr toString
    // -> Tainted)
    // In a real framework this would map to AST Node IDs or Line Numbers
    private final Set<String> taintedSinksFound = new HashSet<>();

    private List<CompilationUnit> cus;

    public void analyze(List<CompilationUnit> cus) {
        this.cus = cus;
        // Phase 1: Identify local sinks, sources, and build the initial parameter taint
        // mappings
        for (CompilationUnit cu : cus) {
            cu.accept(new TaintSourceVisitor(
                    cu.getStorage().map(s -> s.getPath().toAbsolutePath().toString()).orElse("Unknown")), null);
        }

        // Phase 2: Interprocedural propagation (Fixed-Point Iteration)
        propagateTaint();
    }

    /**
     * Checks if a specific finding (identified by method signature) was identified
     * as
     * a tainted sink.
     */
    public boolean isTainted(String methodSignature) {
        return methodSignature != null && taintedSinksFound.contains(methodSignature);
    }

    private void propagateTaint() {
        boolean changed = true;
        int maxIterations = 1000;
        int iterations = 0;

        while (changed && iterations < maxIterations) {
            changed = false;
            iterations++;

            for (CompilationUnit cu : cus) {
                TaintPropagationVisitor visitor = new TaintPropagationVisitor();
                cu.accept(visitor, null);
                if (visitor.hasChanged()) {
                    changed = true;
                }
            }
        }
    }

    private class TaintPropagationVisitor extends VoidVisitorAdapter<Void> {
        private boolean changed = false;

        public boolean hasChanged() {
            return changed;
        }

        @Override
        public void visit(MethodDeclaration md, Void arg) {
            super.visit(md, arg);
            String callerSig = ExposureDetector.getSignature(md);
            // If the caller has any tainted parameters
            Set<Integer> callerTaintedParams = methodTaintedParams.getOrDefault(callerSig, Collections.emptySet());

            md.findAll(MethodCallExpr.class).forEach(call -> {
                String calleeName = call.getNameAsString();

                // Track which arguments passed to callee were tainted
                for (int i = 0; i < call.getArguments().size(); i++) {
                    Expression argExpr = call.getArgument(i);
                    boolean isArgTainted = false;

                    if (argExpr.isNameExpr()) {
                        String varName = argExpr.asNameExpr().getNameAsString();
                        // simplistic check: if an argument name matches a tainted parameter name of the
                        // caller
                        NodeList<Parameter> params = md.getParameters();
                        for (int pIdx : callerTaintedParams) {
                            if (pIdx < params.size() && params.get(pIdx).getNameAsString().equals(varName)) {
                                isArgTainted = true;
                                break;
                            }
                        }
                    }

                    if (isArgTainted) {
                        // In a real resolved AST, we'd look up the exact method signature.
                        // Here we use the approximated name for the structural skeleton.
                        Set<Integer> calleeTainted = methodTaintedParams.computeIfAbsent(".*\\." + calleeName + "\\(.*",
                                k -> new HashSet<>());
                        if (calleeTainted.add(i)) {
                            changed = true;
                        }
                    }
                }
            });
        }
    }

    private class TaintSourceVisitor extends VoidVisitorAdapter<Void> {

        private final String filePath;

        public TaintSourceVisitor(String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void visit(MethodDeclaration md, Void arg) {
            super.visit(md, arg);
            String methodSig = ExposureDetector.getSignature(md);

            // 1. Identify external Taint Sources on Parameters (@RequestBody)
            NodeList<Parameter> parameters = md.getParameters();
            for (int i = 0; i < parameters.size(); i++) {
                Parameter p = parameters.get(i);
                boolean isTaintedSource = p.getAnnotations().stream()
                        .anyMatch(a -> a.getNameAsString().equals("RequestBody"));

                if (isTaintedSource) {
                    methodTaintedParams.computeIfAbsent(methodSig, k -> new HashSet<>()).add(i);
                }
            }

            // 2. Flow-sensitive intra-procedural walk
            Set<String> localTaintedVars = new HashSet<>();

            // Mark source parameters as tainted locally
            if (methodTaintedParams.containsKey(methodSig)) {
                for (int index : methodTaintedParams.get(methodSig)) {
                    localTaintedVars.add(parameters.get(index).getNameAsString());
                }
            }

            // Sequential walk of all expressions in the method (Simplified Flow-Sensitive)
            md.findAll(Expression.class).forEach(expr -> {

                // Rule 1: Inline Sources (request.getParameter)
                if (expr.isMethodCallExpr()) {
                    MethodCallExpr call = expr.asMethodCallExpr();
                    if (call.getNameAsString().equals("getParameter") &&
                            call.getScope().map(s -> s.toString().startsWith("req")).orElse(false)) {

                        // If assigned to a variable, taint it
                        call.findAncestor(VariableDeclarator.class).ifPresent(vd -> {
                            localTaintedVars.add(vd.getNameAsString());
                        });
                        call.findAncestor(AssignExpr.class).ifPresent(ae -> {
                            ae.getTarget().ifNameExpr(n -> localTaintedVars.add(n.getNameAsString()));
                        });
                    }

                    // Rule 2: Taint Sinks (Signature.update, Cipher.doFinal)
                    if (isTaintSink(call)) {
                        // Check if any argument passed is tainted
                        for (Expression argExpr : call.getArguments()) {
                            boolean isArgTainted = false;
                            if (argExpr.isNameExpr()
                                    && localTaintedVars.contains(argExpr.asNameExpr().getNameAsString())) {
                                isArgTainted = true;
                            } else if (argExpr.isMethodCallExpr() && argExpr.asMethodCallExpr().getScope().isPresent()
                                    && argExpr.asMethodCallExpr().getScope().get().isNameExpr()) {
                                if (localTaintedVars.contains(
                                        argExpr.asMethodCallExpr().getScope().get().asNameExpr().getNameAsString())) {
                                    isArgTainted = true;
                                }
                            }

                            if (isArgTainted) {
                                taintedSinksFound.add(methodSig); // Flag method as vulnerable
                            }
                        }
                    }
                }

                // Rule 3: Propagation (Tainted -> AssignedVar)
                if (expr.isAssignExpr()) {
                    AssignExpr assign = expr.asAssignExpr();
                    if (assign.getValue().isNameExpr()
                            && localTaintedVars.contains(assign.getValue().asNameExpr().getNameAsString())) {
                        assign.getTarget().ifNameExpr(n -> localTaintedVars.add(n.getNameAsString()));
                    }
                }
            });
        }

        private boolean isTaintSink(MethodCallExpr call) {
            String name = call.getNameAsString();
            if (name.equals("update")) {
                return call.getScope().map(s -> s.toString().toLowerCase().contains("signature") ||
                        s.toString().toLowerCase().contains("sig")).orElse(false);
            }
            if (name.equals("doFinal")) {
                return call.getScope().map(s -> s.toString().toLowerCase().contains("cipher")).orElse(false);
            }
            return false;
        }
    }
}
