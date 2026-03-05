package com.pqc.analyzer.risk;

public class QuantumRiskModel {

    // --- Configurable Weight Constants ---

    // Algorithm Risk Weights (0.0 to 1.0)
    // Vulnerable algorithms according to Shor's algorithm
    private static final double WEIGHT_ALGO_RSA = 1.0;
    private static final double WEIGHT_ALGO_ECC = 1.0;
    private static final double WEIGHT_ALGO_DSA = 1.0;
    private static final double WEIGHT_ALGO_DH = 1.0;

    // Quantum-safe / Symmetric (No immediate quantum risk from Shor's)
    private static final double WEIGHT_ALGO_AES = 0.0;
    private static final double WEIGHT_ALGO_UNKNOWN = 0.5; // Unknown algorithms carry moderate risk assumption

    // Key Size Weights (Multiplier)
    // Smaller keys break faster, even classically.
    private static final double MULTIPLIER_KEY_WEAK = 1.2;
    private static final double MULTIPLIER_KEY_STANDARD = 1.0;
    private static final double MULTIPLIER_KEY_STRONG = 0.8;

    // Exposure Level Weights (0.0 to 1.0)
    // How easily can an attacker access the ciphertext or public key?
    private static final double WEIGHT_EXP_HIGH = 1.0; // e.g., Network transmission
    private static final double WEIGHT_EXP_MEDIUM = 0.6; // e.g., Database storage
    private static final double WEIGHT_EXP_LOW = 0.2; // e.g., Local ephemeral memory
    private static final double WEIGHT_EXP_UNKNOWN = 0.5;

    // Usage Category Weights (Multiplier)
    // What is the cryptographic primitive protecting?
    private static final double MULTIPLIER_USAGE_KEY_EXCHANGE = 1.5; // Harvest-Now-Decrypt-Later critical
    private static final double MULTIPLIER_USAGE_SIGNATURE = 0.8; // Typically real-time spoofing risk, less HNDL
    private static final double MULTIPLIER_USAGE_ENCRYPTION = 1.2; // High confidentiality risk
    private static final double MULTIPLIER_USAGE_UNKNOWN = 1.0;

    /**
     * Computes the Quantum Risk Score (QRS) for a single cryptographic finding.
     * The score is strictly normalized between 0.0 and 100.0.
     * 
     * @param algorithm     The cryptographic algorithm (e.g., "RSA", "AES").
     * @param keySize       The size of the key in bits, if known (can be null).
     * @param exposureLevel Where the data goes (e.g., "HIGH", "MEDIUM", "LOW").
     * @param usageCategory Context of usage (e.g., "KEY_EXCHANGE", "SIGNATURE").
     * @return A double representing the QRS (0.0 - 100.0).
     */
    public double computeRiskScore(String algorithm, Integer keySize, String exposureLevel, String usageCategory) {

        // 1. Base Algorithm Score
        double baseScore = getAlgorithmWeight(algorithm);
        if (baseScore == 0.0) {
            // Fast fail: If the algorithm isn't vulnerable to quantum attacks (e.g. AES),
            // risk is 0.
            return 0.0;
        }

        // 2. Exposure Weight
        double exposureWeight = getExposureWeight(exposureLevel);

        // 3. Modifiers (Key Size & Usage)
        double keyModifier = getKeySizeModifier(algorithm, keySize);
        double usageModifier = getUsageModifier(usageCategory);

        // 4. Calculate Raw Score
        // Base max theoretical score before modifiers = 1.0 (Algo) * 1.0 (Exposure) =
        // 1.0
        // Max theoretical with modifiers = 1.0 * 1.0 * 1.2 (Key) * 1.5 (Usage) = 1.8
        double rawScore = baseScore * exposureWeight * keyModifier * usageModifier;

        // 5. Normalize specifically to 0.0 - 100.0 range.
        // We define the absolute theoretical maximum possible raw score structurally:
        double theoreticalMax = 1.0 * WEIGHT_EXP_HIGH * MULTIPLIER_KEY_WEAK * MULTIPLIER_USAGE_KEY_EXCHANGE; // 1.8

        double normalizedScore = (rawScore / theoreticalMax) * 100.0;

        // Clamp to bounds to ensure mathematical safety
        return Math.max(0.0, Math.min(100.0, normalizedScore));
    }

    private double getAlgorithmWeight(String algorithm) {
        if (algorithm == null)
            return WEIGHT_ALGO_UNKNOWN;
        String upperAlgo = algorithm.toUpperCase();

        if (upperAlgo.contains("RSA"))
            return WEIGHT_ALGO_RSA;
        if (upperAlgo.contains("EC") || upperAlgo.contains("ELLIPTIC"))
            return WEIGHT_ALGO_ECC;
        if (upperAlgo.contains("DSA"))
            return WEIGHT_ALGO_DSA;
        if (upperAlgo.contains("DH") || upperAlgo.contains("DIFFIE"))
            return WEIGHT_ALGO_DH;

        if (upperAlgo.contains("AES") || upperAlgo.contains("CHACHA"))
            return WEIGHT_ALGO_AES;

        return WEIGHT_ALGO_UNKNOWN;
    }

    private double getExposureWeight(String exposureLevel) {
        if (exposureLevel == null)
            return WEIGHT_EXP_UNKNOWN;
        switch (exposureLevel.toUpperCase()) {
            case "HIGH":
                return WEIGHT_EXP_HIGH;
            case "MEDIUM":
                return WEIGHT_EXP_MEDIUM;
            case "LOW":
                return WEIGHT_EXP_LOW;
            default:
                return WEIGHT_EXP_UNKNOWN;
        }
    }

    private double getKeySizeModifier(String algorithm, Integer keySize) {
        if (keySize == null || algorithm == null)
            return MULTIPLIER_KEY_STANDARD;

        String upperAlgo = algorithm.toUpperCase();

        // RSA heuristics
        if (upperAlgo.contains("RSA")) {
            if (keySize < 2048)
                return MULTIPLIER_KEY_WEAK;
            if (keySize >= 4096)
                return MULTIPLIER_KEY_STRONG;
            return MULTIPLIER_KEY_STANDARD;
        }

        // ECC heuristics
        if (upperAlgo.contains("EC")) {
            if (keySize < 256)
                return MULTIPLIER_KEY_WEAK;
            if (keySize >= 384)
                return MULTIPLIER_KEY_STRONG;
            return MULTIPLIER_KEY_STANDARD;
        }

        return MULTIPLIER_KEY_STANDARD;
    }

    private double getUsageModifier(String usageCategory) {
        if (usageCategory == null)
            return MULTIPLIER_USAGE_UNKNOWN;
        switch (usageCategory.toUpperCase()) {
            case "KEY_EXCHANGE":
                return MULTIPLIER_USAGE_KEY_EXCHANGE;
            case "SIGNATURE":
                return MULTIPLIER_USAGE_SIGNATURE;
            case "ENCRYPTION":
                return MULTIPLIER_USAGE_ENCRYPTION;
            default:
                return MULTIPLIER_USAGE_UNKNOWN;
        }
    }
}
