package io.github.mugishajc.security;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * AES-256 in Galois/Counter Mode.
 *
 * <p>GCM gives confidentiality and integrity in one pass: any change to the
 * ciphertext, IV or associated data makes decryption fail instead of returning
 * garbage. A fresh 96-bit IV is drawn from {@link java.security.SecureRandom}
 * for every message and stored in front of the ciphertext, so callers never
 * have to manage IVs themselves.
 *
 * <p>Wire format: {@code IV (12 bytes) || ciphertext || tag (16 bytes)}.
 *
 * <p>Note: with random IVs, NIST recommends staying under roughly 2^32
 * messages per key. Rotate keys well before that.
 */
public final class AesGcm {

    public static final int KEY_BYTES = 32;
    public static final int IV_BYTES = 12;
    public static final int TAG_BITS = 128;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final byte[] NO_AAD = new byte[0];

    private final SecretKey key;

    private AesGcm(SecretKey key) {
        this.key = key;
    }

    /** Creates a cipher around a freshly generated 256-bit key. */
    public static AesGcm withNewKey() {
        return new AesGcm(generateKey());
    }

    public static AesGcm withKey(SecretKey key) {
        Objects.requireNonNull(key, "key");
        byte[] encoded = key.getEncoded();
        if (!"AES".equalsIgnoreCase(key.getAlgorithm()) || encoded == null || encoded.length != KEY_BYTES) {
            throw new IllegalArgumentException("expected a 256-bit AES key");
        }
        return new AesGcm(key);
    }

    public static AesGcm withKey(byte[] rawKey) {
        Objects.requireNonNull(rawKey, "rawKey");
        if (rawKey.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-256 needs a 32-byte key, got " + rawKey.length);
        }
        return new AesGcm(new SecretKeySpec(rawKey.clone(), "AES"));
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(KEY_BYTES * 8);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("AES is not available on this JVM", e);
        }
    }

    public SecretKey key() {
        return key;
    }

    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, NO_AAD);
    }

    /**
     * Encrypts {@code plaintext}. The associated data is authenticated but not
     * encrypted, which is useful for binding a ciphertext to a context such as
     * a user id or record id so it cannot be replayed elsewhere.
     */
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(associatedData, "associatedData");
        byte[] iv = SecureTokens.randomBytes(IV_BYTES);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(associatedData);
            byte[] sealed = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(iv.length + sealed.length).put(iv).put(sealed).array();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] message) {
        return decrypt(message, NO_AAD);
    }

    /**
     * Decrypts a message produced by {@link #encrypt(byte[], byte[])}.
     *
     * @throws IntegrityException if the message was modified, the wrong key
     *                            was used, or the associated data differs
     */
    public byte[] decrypt(byte[] message, byte[] associatedData) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(associatedData, "associatedData");
        if (message.length < IV_BYTES + TAG_BITS / 8) {
            throw new IntegrityException("message is too short to be valid");
        }
        byte[] iv = Arrays.copyOfRange(message, 0, IV_BYTES);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(associatedData);
            return cipher.doFinal(message, IV_BYTES, message.length - IV_BYTES);
        } catch (AEADBadTagException e) {
            throw new IntegrityException("authentication tag mismatch", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("decryption failed", e);
        }
    }

    /** Convenience wrapper: UTF-8 text in, Base64 out. */
    public String encryptToBase64(String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        return Base64.getEncoder().encodeToString(encrypt(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    public String decryptFromBase64(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        byte[] message;
        try {
            message = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IntegrityException("input is not valid Base64", e);
        }
        return new String(decrypt(message), StandardCharsets.UTF_8);
    }
}
