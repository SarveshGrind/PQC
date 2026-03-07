package com.pqc.analyzer.usage;

import com.pqc.analyzer.model.CryptoFinding;

import java.util.List;

public class CryptoUsageAnalyzer {

    /**
     * Determines the cryptographic usage type (ENCRYPTION, SIGNATURE,
     * KEY_EXCHANGE, CERTIFICATE_SIGNATURE, UNKNOWN) based on the specific API class
     * identified.
     */
    public void analyze(List<CryptoFinding> findings) {
        for (CryptoFinding finding : findings) {
            if (finding.apiClass == null) {
                finding.usageType = "UNKNOWN";
                continue;
            }

            String cls = finding.apiClass;

            if (cls.equals("Cipher")) {
                finding.usageType = "ENCRYPTION";
            } else if (cls.equals("Signature")) {
                finding.usageType = "SIGNATURE";
            } else if (cls.equals("KeyAgreement")) {
                finding.usageType = "KEY_EXCHANGE";
            } else if (cls.equals("CertificateFactory") || cls.equals("X509Certificate")) {
                finding.usageType = "CERTIFICATE_SIGNATURE";
            } else if (cls.equals("KeyFactory") || cls.equals("KeyPairGenerator") || cls.equals("KeyGenerator")
                    || cls.equals("RSAKeyGenerator")) {
                finding.usageType = "KEY_GENERATION";
            } else if (cls.equals("KeyStore")) {
                finding.usageType = "CERTIFICATE";
            } else {
                finding.usageType = "UNKNOWN";
            }
        }
    }
}
