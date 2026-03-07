package com.pqc.analyzer.model;

public class RiskSummary {
    public double qrs;
    public int totalFindings;
    public int highRiskCount;

    public RiskSummary(double qrs, int totalFindings, int highRiskCount) {
        this.qrs = qrs;
        this.totalFindings = totalFindings;
        this.highRiskCount = highRiskCount;
    }
}
