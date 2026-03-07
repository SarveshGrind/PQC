package com.pqc.analyzer.model;

import java.util.List;

public class AnalyzerResponse {
    private String analyzerVersion;
    private RiskSummary summary;
    private List<CryptoFinding> findings;

    public AnalyzerResponse(String analyzerVersion, RiskSummary summary, List<CryptoFinding> findings) {
        this.analyzerVersion = analyzerVersion;
        this.summary = summary;
        this.findings = findings;
    }

    public List<CryptoFinding> getFindings() {
        return findings;
    }
}
