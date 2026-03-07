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
            "Cipher",
            "KeyFactory",
            "RSAKeyGenerator",
            "KeyGenerator",
            "KeyAgreement",
            "CertificateFactory",
            "X509Certificate");

    public List<CryptoFinding> analyzeRepository(String repoPath) {
        // Configure JavaParser for modern Java 17 features
        com.github.javaparser.ParserConfiguration config = new com.github.javaparser.ParserConfiguration()
                .setLanguageLevel(com.github.javaparser.ParserConfiguration.LanguageLevel.JAVA_17);
        StaticJavaParser.setConfiguration(config);

        List<CryptoFinding> findings = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(Paths.get(repoPath))) {
            List<File> javaFiles = paths.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toFile).toList();

            System.err.println("CryptoDetector: Scanned " + javaFiles.size() + " Java files.");

            for (File p : javaFiles) {
                findings.addAll(analyzeFile(p));
            }
        } catch (IOException e) {
            System.err.println("Error walking repository path: " + e.getMessage());
        }

        System.err.println("CryptoDetector: Detected " + findings.size() + " cryptographic APIs.");
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
        public void visit(com.github.javaparser.ast.body.VariableDeclarator n, List<CryptoFinding> findings) {
            super.visit(n, findings);

            String typeName = n.getTypeAsString();
            String algorithm = null;

            if (typeName.equals("RSAPublicKey") || typeName.equals("RSAPrivateKey") || typeName.equals("RSAKey")) {
                algorithm = "RSA";
            } else if (typeName.equals("ECPublicKey") || typeName.equals("ECPrivateKey") || typeName.equals("ECKey")) {
                algorithm = "EC";
            }

            if (algorithm != null) {
                int lineNumber = n.getBegin().map(pos -> pos.line).orElse(-1);
                CryptoFinding finding = new CryptoFinding(filePath, lineNumber, algorithm, null);
                finding.apiClass = typeName; // Variables directly provide the type context (e.g. RSAPublicKey)

                n.findAncestor(com.github.javaparser.ast.body.MethodDeclaration.class).ifPresent(md -> {
                    finding.methodSignature = com.pqc.analyzer.exposure.ExposureDetector.getSignature(md);
                });

                findings.add(finding);
            }
        }

        @Override
        public void visit(com.github.javaparser.ast.expr.ObjectCreationExpr n, List<CryptoFinding> findings) {
            super.visit(n, findings);

            String typeName = n.getTypeAsString();
            if (typeName.equals("ECGenParameterSpec") && n.getArguments().size() > 0
                    && n.getArgument(0).isStringLiteralExpr()) {
                String curveStr = n.getArgument(0).asStringLiteralExpr().getValue();
                String algo = "EC";
                Integer keySize = null;

                // Attempt to parse out basic standard curve bit lengths like secp256r1
                if (curveStr.contains("256"))
                    keySize = 256;
                else if (curveStr.contains("384"))
                    keySize = 384;
                else if (curveStr.contains("521"))
                    keySize = 521;

                int lineNumber = n.getBegin().map(pos -> pos.line).orElse(-1);
                CryptoFinding finding = new CryptoFinding(filePath, lineNumber, algo, keySize);
                finding.apiClass = typeName;
                n.findAncestor(com.github.javaparser.ast.body.MethodDeclaration.class).ifPresent(md -> {
                    finding.methodSignature = com.pqc.analyzer.exposure.ExposureDetector.getSignature(md);
                });
                findings.add(finding);
            }
        }

        @Override
        public void visit(MethodCallExpr n, List<CryptoFinding> findings) {
            super.visit(n, findings);

            String methodName = n.getNameAsString();

            // Extract KeySize from initialize calls
            if (methodName.equals("initialize") && n.getArguments().size() > 0) {
                n.getScope().ifPresent(scope -> {
                    // Try to extract exact integer literal keysize if passed statically
                    if (n.getArgument(0).isIntegerLiteralExpr()) {
                        int ks = n.getArgument(0).asIntegerLiteralExpr().asNumber().intValue();
                        int lineNumber = n.getBegin().map(pos -> pos.line).orElse(-1);
                        // Search findings in same file around same line or method if we want to
                        // associate,
                        // but simplest AST logic without sym solver is just emit the finding. We can
                        // use
                        // the scope type if known, but simple regex on scope name or standalone emit is
                        // safer.
                        CryptoFinding finding = new CryptoFinding(filePath, lineNumber, "UNKNOWN", ks);
                        n.findAncestor(com.github.javaparser.ast.body.MethodDeclaration.class).ifPresent(md -> {
                            finding.methodSignature = com.pqc.analyzer.exposure.ExposureDetector.getSignature(md);
                        });
                        findings.add(finding);
                    }
                });
            }

            if (methodName.equals("getInstance")) {
                n.getScope().ifPresent(scope -> {
                    String scopeName = scope.toString();
                    if (TARGET_CLASSES.contains(scopeName)) {

                        String algorithm = "UNKNOWN";
                        // Attempt to extract algorithm string if it's a literal
                        if (n.getArguments().size() > 0 && n.getArgument(0).isStringLiteralExpr()) {
                            StringLiteralExpr literal = n.getArgument(0).asStringLiteralExpr();
                            algorithm = literal.getValue();

                            // Map generic factory calls appropriately
                            if (algorithm.equalsIgnoreCase("RSA"))
                                algorithm = "RSA";
                            else if (algorithm.equalsIgnoreCase("EC"))
                                algorithm = "EC";
                        }

                        int lineNumber = n.getBegin().map(pos -> pos.line).orElse(-1);

                        CryptoFinding finding = new CryptoFinding(filePath, lineNumber, algorithm, null);
                        finding.apiClass = scopeName;

                        // Extract Method Signature to support Exposure Analysis
                        n.findAncestor(com.github.javaparser.ast.body.MethodDeclaration.class).ifPresent(md -> {
                            finding.methodSignature = com.pqc.analyzer.exposure.ExposureDetector.getSignature(md);
                        });

                        findings.add(finding);
                    }
                });
            }
        }
    }
}
