package com.pqc.analyzer.pipeline;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.pqc.analyzer.detection.CryptoDetector;
import com.pqc.analyzer.exposure.ExposureDetector;
import com.pqc.analyzer.model.AnalyzerResponse;
import com.pqc.analyzer.model.CryptoFinding;
import com.pqc.analyzer.model.RiskSummary;
import com.pqc.analyzer.risk.QuantumRiskModel;
import com.pqc.analyzer.taint.TaintAnalyzer;
import com.pqc.analyzer.usage.CryptoUsageAnalyzer;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AnalyzerPipeline {

    private static final String ANALYZER_VERSION = "1.0.0";

    // 1. Detection
    private final CryptoDetector detector = new CryptoDetector();

    // 2. Exposure Modeling
    private final ExposureDetector exposureDetector = new ExposureDetector();

    // 3. Taint Analysis
    private final TaintAnalyzer taintAnalyzer = new TaintAnalyzer();

    // 4. Usage Analysis
    private final CryptoUsageAnalyzer usageAnalyzer = new CryptoUsageAnalyzer();

    // 5. Risk Scoring
    private final QuantumRiskModel riskModel = new QuantumRiskModel();

    public AnalyzerResponse run(String repoPath) {

        // --- Phase 0: Centralized AST Parsing ---
        // Parse all Java files once to share the AST across modules and avoid redundant
        // I/O.
        List<CompilationUnit> cus = parseAllJavaFiles(repoPath);

        // --- Phase 1: Detection ---
        // Note: CryptoDetector currently parses files internally as well. To fully
        // optimize,
        // CryptoDetector should be refactored to accept List<CompilationUnit>, but per
        // constraints
        // we keep its external contract intact and run it independently for now.
        List<CryptoFinding> initialFindings = detector.analyzeRepository(repoPath);

        // --- Phase 2: Usage Classification ---
        usageAnalyzer.analyze(initialFindings);

        // --- Phase 3: Exposure Classification ---
        // Builds the interprocedural call graph to classify structural reachability
        exposureDetector.buildCallGraphAndBaseExposure(cus);
        exposureDetector.propagateExposure();

        // --- Phase 4: Taint Propagation ---
        // Models data flow from sources (@RequestBody) to sinks (Signature.update)
        taintAnalyzer.analyze(cus);

        // --- Integration & Phase 5: Risk Scoring ---
        double aggregateRisk = 0.0;
        int highRiskCount = 0;

        for (CryptoFinding finding : initialFindings) {

            // Integrate Exposure
            // To properly link the finding to the AST, we need the method signature from
            // Detection
            String exposureLevel = "LOW";
            if (finding.methodSignature != null) {
                exposureLevel = exposureDetector.getExposureLevel(finding.methodSignature);
            }
            finding.exposureLevel = exposureLevel;

            // Integrate Taint
            boolean isTainted = finding.methodSignature != null && taintAnalyzer.isTainted(finding.methodSignature);
            finding.setTainted(isTainted);

            // In a real integration, the usage category would also map from AST context.
            finding.usageCategory = "Data in Transit / Data at Rest";

            // Step 3 Map PQC Replacement Matcher based on Usage Type
            if (finding.usageType != null) {
                switch (finding.usageType) {
                    case "ENCRYPTION":
                    case "KEY_EXCHANGE":
                        finding.recommendedReplacement = "CRYSTALS-Kyber";
                        break;
                    case "SIGNATURE":
                    case "CERTIFICATE_SIGNATURE":
                        finding.recommendedReplacement = "CRYSTALS-Dilithium";
                        break;
                    default:
                        if ("RSA".equals(finding.algorithm)) {
                            finding.recommendedReplacement = "CRYSTALS-Kyber";
                        } else if ("EC".equals(finding.algorithm)) {
                            finding.recommendedReplacement = "CRYSTALS-Dilithium";
                        } else {
                            finding.recommendedReplacement = "Unknown";
                        }
                        break;
                }
            } else {
                if ("RSA".equals(finding.algorithm)) {
                    finding.recommendedReplacement = "CRYSTALS-Kyber";
                } else if ("EC".equals(finding.algorithm)) {
                    finding.recommendedReplacement = "CRYSTALS-Dilithium";
                } else {
                    finding.recommendedReplacement = "Unknown";
                }
            }

            // Step 4 Compute Final Risk Score
            finding.riskScore = riskModel.computeRiskScore(
                    finding.algorithm,
                    finding.keySize,
                    exposureLevel,
                    isTainted);
            if (finding.riskScore >= 80.0) {
                highRiskCount++;
            }
            aggregateRisk += finding.riskScore;
            System.err.println("Finding: " + finding.algorithm + " @ " + finding.filePath + ":" + finding.lineNumber
                    + " -> BaseExp: " + exposureLevel + ", Tainted: " + isTainted + ", Risk: " + finding.riskScore);
        }

        // Calculate a simple system-wide Quantum Risk Score (Average)
        double finalSystemQrs = initialFindings.isEmpty() ? 0.0 : (aggregateRisk / initialFindings.size());
        RiskSummary summary = new RiskSummary(finalSystemQrs, initialFindings.size(), highRiskCount);

        System.err.println("Pipeline Integration complete: Total QRS " + finalSystemQrs + ", Total Findings "
                + initialFindings.size() + ", High Risk " + highRiskCount);

        return new AnalyzerResponse(ANALYZER_VERSION, summary, initialFindings);
    }

    private List<CompilationUnit> parseAllJavaFiles(String repoPath) {
        // Configure JavaParser for modern Java 17 features (records, switch
        // expressions, text blocks, etc.)
        com.github.javaparser.ParserConfiguration config = new com.github.javaparser.ParserConfiguration()
                .setLanguageLevel(com.github.javaparser.ParserConfiguration.LanguageLevel.JAVA_17);
        StaticJavaParser.setConfiguration(config);

        List<CompilationUnit> cus = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(Paths.get(repoPath))) {
            List<File> javaFiles = paths.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toFile)
                    .collect(Collectors.toList());

            for (File file : javaFiles) {
                try {
                    cus.add(StaticJavaParser.parse(file));
                } catch (Exception e) {
                    System.err.println("Pipeline failed to parse: " + file.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            System.err.println("Pipeline error reading repo: " + e.getMessage());
        }
        return cus;
    }
}
