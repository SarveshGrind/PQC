package com.pqc.analyzer.model;

public class CryptoFinding {
    public String filePath;
    public int lineNumber;
    public String algorithm;
    public Integer keySize;
    public String exposureLevel;
    public boolean tainted;
    public String usageCategory;
    public double riskScore;
    public String recommendedReplacement;
    public String usageType;
    public transient String methodSignature;
    public transient String apiClass;

    public CryptoFinding(String filePath, int lineNumber, String algorithm, Integer keySize) {
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.algorithm = algorithm;
        this.keySize = keySize;
        // Default values for fields not yet implemented
        this.exposureLevel = "UNKNOWN";
        this.tainted = false;
        this.usageCategory = "UNKNOWN";
        this.usageType = "UNKNOWN";
        this.riskScore = 0.0;
        this.recommendedReplacement = "Unknown";
    }

    public void setTainted(boolean tainted) {
        this.tainted = tainted;
    }

    // Getters and setters (omitted for brevity, Gson relies on reflection for
    // private fields)
}
