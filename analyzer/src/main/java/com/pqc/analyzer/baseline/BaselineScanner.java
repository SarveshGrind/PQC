package com.pqc.analyzer.baseline;

import com.pqc.analyzer.model.AnalyzerResponse;
import com.pqc.analyzer.model.CryptoFinding;
import com.pqc.analyzer.model.RiskSummary;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A naive Baseline Scanner used strictly for Evaluation comparisons.
 * It does NOT use AST parsing, Taint Analysis, or Structural Exposure modeling.
 * It purely uses simple string matching (grep-style) to find "RSA" or "ECC".
 */
public class BaselineScanner {

    private static final String ANALYZER_VERSION = "0.1.0-BASELINE";

    public AnalyzerResponse run(String repoPath) {
        List<CryptoFinding> findings = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(Paths.get(repoPath))) {
            List<File> javaFiles = paths.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .map(Path::toFile)
                    .collect(Collectors.toList());

            for (File file : javaFiles) {
                findings.addAll(scanFile(file));
            }
        } catch (IOException e) {
            System.err.println("BaselineScanner error reading repo: " + e.getMessage());
        }

        // Baseline model treats all findings as uniformly risky without nuance
        double baselineQrs = findings.isEmpty() ? 0.0 : 80.0;
        RiskSummary summary = new RiskSummary(baselineQrs);

        return new AnalyzerResponse(ANALYZER_VERSION, summary, findings);
    }

    private List<CryptoFinding> scanFile(File file) {
        List<CryptoFinding> fileFindings = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNumber = 1;

            while ((line = reader.readLine()) != null) {
                String upperLine = line.toUpperCase();

                // Naive keyword matching
                if (upperLine.contains("RSA")) {
                    fileFindings.add(createBaselineFinding(file.getAbsolutePath(), lineNumber, "RSA"));
                } else if (upperLine.contains("ECC") || upperLine.contains("ELLIPTIC")) {
                    fileFindings.add(createBaselineFinding(file.getAbsolutePath(), lineNumber, "ECC"));
                }

                lineNumber++;
            }
        } catch (IOException e) {
            System.err.println("Error reading file in BaselineScanner: " + file.getAbsolutePath());
        }

        return fileFindings;
    }

    private CryptoFinding createBaselineFinding(String filePath, int lineNumber, String algorithm) {
        // Baseline has zero knowledge of key size, taint, exposure, or usage.
        // It strictly populates the mandatory contract fields with default/unknown
        // values.
        CryptoFinding finding = new CryptoFinding(filePath, lineNumber, algorithm, null);
        finding.exposureLevel = "UNKNOWN";
        finding.tainted = false;
        finding.usageCategory = "UNKNOWN";
        finding.riskScore = 80.0; // Static generic risk score
        return finding;
    }
}
