package io.github.mugishajc.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * The public-key signature schemes supported by {@link DigitalSignatures}.
 *
 * <p>Plain {@code SHA256withRSA} (PKCS#1 v1.5) is deliberately left out in
 * favour of PSS, which has a security proof and no padding-oracle history.
 */
public enum SignatureScheme {

    /** RSASSA-PSS, 3072-bit modulus, SHA-256, MGF1-SHA-256, 32-byte salt. */
    RSA_PSS_SHA256("RSA", "RSASSA-PSS") {
        @Override
        void initialize(KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
            generator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        }

        @Override
        AlgorithmParameterSpec signatureParameters() {
            return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        }
    },

    /** ECDSA on NIST P-256 with SHA-256, DER-encoded signatures. */
    ECDSA_P256_SHA256("EC", "SHA256withECDSA") {
        @Override
        void initialize(KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        }

        @Override
        AlgorithmParameterSpec signatureParameters() {
            return null;
        }
    };

    private final String keyAlgorithm;
    private final String signatureAlgorithm;

    SignatureScheme(String keyAlgorithm, String signatureAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    String keyAlgorithm() {
        return keyAlgorithm;
    }

    abstract void initialize(KeyPairGenerator generator) throws InvalidAlgorithmParameterException;

    abstract AlgorithmParameterSpec signatureParameters();

    Signature newSignature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        AlgorithmParameterSpec params = signatureParameters();
        if (params != null) {
            signature.setParameter(params);
        }
        return signature;
    }
}
