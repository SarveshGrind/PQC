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

    public CryptoFinding(String filePath, int lineNumber, String algorithm, Integer keySize) {
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.algorithm = algorithm;
        this.keySize = keySize;
        // Default values for fields not yet implemented
        this.exposureLevel = "UNKNOWN";
        this.tainted = false;
        this.usageCategory = "UNKNOWN";
        this.riskScore = 0.0;
    }

    public void setTainted(boolean tainted) {
        this.tainted = tainted;
    }

    // Getters and setters (omitted for brevity, Gson relies on reflection for
    // private fields)
}
