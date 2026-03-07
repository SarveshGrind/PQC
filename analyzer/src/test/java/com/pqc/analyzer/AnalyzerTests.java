package com.pqc.analyzer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.pqc.analyzer.detection.CryptoDetector;
import com.pqc.analyzer.exposure.ExposureDetector;
import com.pqc.analyzer.model.AnalyzerResponse;
import com.pqc.analyzer.model.CryptoFinding;
import com.pqc.analyzer.pipeline.AnalyzerPipeline;
import com.pqc.analyzer.risk.QuantumRiskModel;
import com.pqc.analyzer.taint.TaintAnalyzer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AnalyzerTests {

    @Test
    void testRiskScoring() {
        QuantumRiskModel model = new QuantumRiskModel();
        // RSA, High Exposure, Tainted -> Base 80 + 10 + 10 = 100 > 80
        double score = model.computeRiskScore("SHA256withRSA", 2048, "HIGH", true);
        assertTrue(score >= 80.0, "Score should be >= 80");
        assertEquals(100.0, score, 0.01);

        // AES -> Base 0
        double aesScore = model.computeRiskScore("AES/GCM/NoPadding", 256, "LOW", false);
        assertEquals(0.0, aesScore, 0.01);
    }

    @Test
    void testIntegrationAndUnitVerification(@TempDir Path tempDir) throws Exception {
        // Step 18 Test Controller code
        String testCode = "@RestController\n" +
                "class TestController {\n" +
                "  public void login(HttpServletRequest req) throws Exception {\n" +
                "      String password = req.getParameter(\"password\");\n" +
                "      Signature sig = Signature.getInstance(\"SHA256withRSA\");\n" +
                "      sig.update(password.getBytes());\n" +
                "  }\n" +
                "}";

        File testFile = tempDir.resolve("TestController.java").toFile();
        Files.writeString(testFile.toPath(), testCode);

        // Unit Test: Detection
        CryptoDetector detector = new CryptoDetector();
        List<CryptoFinding> findings = detector.analyzeRepository(tempDir.toString());
        assertEquals(1, findings.size(), "Should detect exactly 1 cryptographic API");
        assertEquals("RSA", findings.get(0).algorithm);

        // Unit Test: Exposure
        CompilationUnit cu = StaticJavaParser.parse(testFile);
        ExposureDetector exposureDetector = new ExposureDetector();
        exposureDetector.buildCallGraphAndBaseExposure(Collections.singletonList(cu));
        exposureDetector.propagateExposure();
        String sig = findings.get(0).methodSignature;
        assertNotNull(sig, "Method signature must be extracted");
        assertEquals("HIGH", exposureDetector.getExposureLevel(sig),
                "Exposure level should be HIGH because of @RestController");

        // Unit Test: Taint
        TaintAnalyzer taintAnalyzer = new TaintAnalyzer();
        taintAnalyzer.analyze(Collections.singletonList(cu));
        assertTrue(taintAnalyzer.isTainted(findings.get(0).methodSignature),
                "Signature.update should be flagged as tainted sink based on getParameter flow");

        // Integration Test: Pipeline
        AnalyzerPipeline pipeline = new AnalyzerPipeline();
        AnalyzerResponse response = pipeline.run(tempDir.toString());

        // Verify Step 17 and Step 18 Final Requirements
        List<CryptoFinding> finalFindings = response.getFindings();
        assertEquals(1, finalFindings.size(), "Should have exactly 1 finding");

        CryptoFinding mainFinding = finalFindings.get(0);
        assertEquals("RSA", mainFinding.algorithm, "Algorithm must match");
        assertEquals("HIGH", mainFinding.exposureLevel, "Exposure must be HIGH");
        assertTrue(mainFinding.tainted, "Taint must be true");
        assertTrue(mainFinding.riskScore >= 80.0, "Risk score must be at least 80.0 for RSA+HIGH+Tainted");
    }

    @Test
    void testTypeInferenceAndFallbackPQC(@TempDir Path tempDir) throws Exception {
        String testCode = "import java.security.interfaces.RSAPublicKey;\n" +
                "class TestTypeInference {\n" +
                "  public void useKey() {\n" +
                "      RSAPublicKey key = null;\n" +
                "  }\n" +
                "}";

        File testFile = tempDir.resolve("TestTypeInference.java").toFile();
        Files.writeString(testFile.toPath(), testCode);

        AnalyzerPipeline pipeline = new AnalyzerPipeline();
        AnalyzerResponse response = pipeline.run(tempDir.toString());

        List<CryptoFinding> findings = response.getFindings();
        assertEquals(1, findings.size(), "Should detect exactly 1 cryptographic API from type inference");

        CryptoFinding finding = findings.get(0);
        assertEquals("RSA", finding.algorithm);
        // "RSAPublicKey" is not explicitly mapped in CryptoUsageAnalyzer, so usageType
        // becomes UNKNOWN
        assertEquals("UNKNOWN", finding.usageType);
        // Fallback should map RSA -> CRYSTALS-Kyber
        assertEquals("CRYSTALS-Kyber", finding.recommendedReplacement);
    }
}
