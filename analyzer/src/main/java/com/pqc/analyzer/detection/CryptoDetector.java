package com.pqc.analyzer.detection;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.pqc.analyzer.model.CryptoFinding;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class CryptoDetector {

    private static final List<String> TARGET_CLASSES = Arrays.asList(
            "Signature",
            "KeyPairGenerator",
            "Cipher"
    );

    public List<CryptoFinding> analyzeRepository(String repoPath) {
        List<CryptoFinding> findings = new ArrayList<>();
        
        try (Stream<Path> paths = Files.walk(Paths.get(repoPath))) {
            paths.filter(Files::isRegularFile)
                 .filter(p -> p.toString().endsWith(".java"))
                 .forEach(p -> findings.addAll(analyzeFile(p.toFile())));
        } catch (IOException e) {
            System.err.println("Error walking repository path: " + e.getMessage());
        }

        return findings;
    }

    private List<CryptoFinding> analyzeFile(File javaFile) {
        List<CryptoFinding> fileFindings = new ArrayList<>();
        
        try {
            CompilationUnit cu = StaticJavaParser.parse(javaFile);
            cu.accept(new CryptoNodeVisitor(javaFile.getAbsolutePath()), fileFindings);
        } catch (Exception e) {
            System.err.println("Failed to parse file: " + javaFile.getAbsolutePath() + " - " + e.getMessage());
        }

        return fileFindings;
    }

    private static class CryptoNodeVisitor extends VoidVisitorAdapter<List<CryptoFinding>> {
        private final String filePath;

        public CryptoNodeVisitor(String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void visit(MethodCallExpr n, List<CryptoFinding> findings) {
            super.visit(n, findings);

            if (n.getNameAsString().equals("getInstance")) {
                n.getScope().ifPresent(scope -> {
                    String scopeName = scope.toString();
                    if (TARGET_CLASSES.contains(scopeName)) {
                        
                        String algorithm = "UNKNOWN";
                        // Attempt to extract algorithm string if it's a literal
                        if (n.getArguments().size() > 0 && n.getArgument(0).isStringLiteralExpr()) {
                            StringLiteralExpr literal = n.getArgument(0).asStringLiteralExpr();
                            algorithm = literal.getValue();
                        }

                        int lineNumber = n.getBegin().map(pos -> pos.line).orElse(-1);
                        
                        // Key size extraction requires deeper flow analysis/value resolution
                        // we leave it null per constraints if not statically trivially available
                        findings.add(new CryptoFinding(filePath, lineNumber, algorithm, null));
                    }
                });
            }
        }
    }
}
