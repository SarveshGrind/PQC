package com.pqc.analyzer.risk;

public class QuantumRiskModel {

    /**
     * Computes the Quantum Risk Score (QRS) for a single cryptographic finding.
     * The score is strictly normalized between 0.0 and 100.0.
     * 
     * @param algorithm     The cryptographic algorithm (e.g., "RSA", "AES").
     * @param keySize       The size of the key in bits, if known (can be null).
     * @param exposureLevel Where the data goes (e.g., "HIGH", "MEDIUM", "LOW").
     * @param tainted       Whether the data reaching the crypto sink is tainted.
     * @return A double representing the QRS (0.0 - 100.0).
     */
    public double computeRiskScore(String algorithm, Integer keySize, String exposureLevel, boolean tainted) {
        if (algorithm == null) {
            return 50.0;
        }

        double score = 50.0; // Default base score
        String upperAlgo = algorithm.toUpperCase();

        // Base Algorithm Score
        if (upperAlgo.contains("RSA")) {
            score = 80.0;
        } else if (upperAlgo.contains("EC") || upperAlgo.contains("ELLIPTIC")) {
            score = 75.0;
        } else if (upperAlgo.contains("AES") || upperAlgo.contains("CHACHA")) {
            score = 0.0; // Symmetric algorithms
        }

        // Exposure Modifier
        if ("HIGH".equalsIgnoreCase(exposureLevel)) {
            score += 10.0;
        }

        // Taint Modifier
        if (tainted) {
            score += 10.0;
        }

        // Normalize strictly between 0.0 and 100.0
        return Math.max(0.0, Math.min(score, 100.0));
    }
}
