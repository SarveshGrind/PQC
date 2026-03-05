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

    // 4. Risk Scoring
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

        // --- Phase 2: Exposure Classification ---
        // Builds the interprocedural call graph to classify structural reachability
        exposureDetector.buildCallGraphAndBaseExposure(cus);
        exposureDetector.propagateExposure();

        // --- Phase 3: Taint Propagation ---
        // Models data flow from sources (@RequestBody) to sinks (Signature.update)
        taintAnalyzer.analyze(cus);

        // --- Integration & Phase 4: Risk Scoring ---
        double aggregateRisk = 0.0;

        for (CryptoFinding finding : initialFindings) {

            // Integrate Exposure
            // To properly link the finding to the AST, we need the method signature.
            // For the skeleton, we default to "MEDIUM". In full implementation, the
            // Detection
            // phase would attach the method signature to the CryptoFinding object.
            String exposureLevel = "MEDIUM";

            // Integrate Taint
            // Check if this specific finding location (file + line) is flagged as a tainted
            // sink
            boolean isTainted = taintAnalyzer.isTainted(finding.filePath, finding.lineNumber);
            finding.setTainted(isTainted);

            // In a real integration, the usage category would also map from AST context.
            String usageCategory = "UNKNOWN";

            // Compute Final QRS for this specific finding
            double findingRisk = riskModel.computeRiskScore(
                    finding.algorithm,
                    finding.keySize,
                    exposureLevel,
                    usageCategory);

            // If tainted, we artificially amplify the risk score (simulating combined risk)
            if (isTainted) {
                findingRisk = Math.min(100.0, findingRisk * 1.5);
            }

            finding.riskScore = findingRisk;
            aggregateRisk += findingRisk;
        }

        // Calculate a simple system-wide Quantum Risk Score (Average)
        double finalSystemQrs = initialFindings.isEmpty() ? 0.0 : (aggregateRisk / initialFindings.size());
        RiskSummary summary = new RiskSummary(finalSystemQrs);

        return new AnalyzerResponse(ANALYZER_VERSION, summary, initialFindings);
    }

    private List<CompilationUnit> parseAllJavaFiles(String repoPath) {
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
