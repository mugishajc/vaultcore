package io.github.mugishajc.security;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Sign and verify with RSA-PSS or ECDSA.
 *
 * <p>Unlike HMAC, only the holder of the private key can sign, while anyone
 * with the public key can verify. That makes signatures the right tool when the
 * verifier must not be able to forge messages, e.g. release artifacts, licence
 * files or tokens checked by third parties.
 */
public final class DigitalSignatures {

    private DigitalSignatures() {
    }

    public static KeyPair generateKeyPair(SignatureScheme scheme) {
        Objects.requireNonNull(scheme, "scheme");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(scheme.keyAlgorithm());
            scheme.initialize(generator);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("cannot generate " + scheme + " key pair", e);
        }
    }

    public static byte[] sign(SignatureScheme scheme, PrivateKey privateKey, byte[] data) {
        Objects.requireNonNull(scheme, "scheme");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(data, "data");
        try {
            Signature signature = scheme.newSignature();
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("key does not match " + scheme, e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("signing failed", e);
        }
    }

    /**
     * Returns {@code true} only for a valid signature. Malformed signatures
     * return {@code false} instead of throwing, so attacker-controlled input
     * cannot trigger a different code path.
     */
    public static boolean verify(SignatureScheme scheme, PublicKey publicKey, byte[] data, byte[] signatureBytes) {
        Objects.requireNonNull(scheme, "scheme");
        Objects.requireNonNull(publicKey, "publicKey");
        if (data == null || signatureBytes == null) {
            return false;
        }
        try {
            Signature signature = scheme.newSignature();
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            return false;
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("key does not match " + scheme, e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("verification failed", e);
        }
    }

    /** Encodes a public key as Base64 X.509 SubjectPublicKeyInfo, suitable for config files. */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey decodePublicKey(SignatureScheme scheme, String encoded) {
        Objects.requireNonNull(scheme, "scheme");
        Objects.requireNonNull(encoded, "encoded");
        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            return KeyFactory.getInstance(scheme.keyAlgorithm()).generatePublic(new X509EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new IllegalArgumentException("not a valid " + scheme.keyAlgorithm() + " public key", e);
        }
    }
}
