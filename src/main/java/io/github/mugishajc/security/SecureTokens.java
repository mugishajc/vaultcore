package io.github.mugishajc.security;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Generates unpredictable tokens for things like session ids, password-reset
 * links, CSRF tokens and API keys.
 *
 * <p>Uses {@link SecureRandom} rather than {@link java.util.Random} or
 * {@code Math.random()}, whose output can be predicted after observing a few values.
 */
public final class SecureTokens {

    /** 32 bytes = 256 bits, comfortably beyond brute force. */
    public static final int DEFAULT_BYTES = 32;

    /** Anything shorter than 128 bits is too easy to guess for a bearer token. */
    static final int MIN_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private SecureTokens() {
    }

    /** Returns {@code length} random bytes. */
    public static byte[] randomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /** A 256-bit token encoded as URL-safe Base64 without padding (43 characters). */
    public static String urlSafeToken() {
        return urlSafeToken(DEFAULT_BYTES);
    }

    public static String urlSafeToken(int byteLength) {
        requireStrength(byteLength);
        return URL_ENCODER.encodeToString(randomBytes(byteLength));
    }

    /** A 256-bit token encoded as lowercase hex (64 characters). */
    public static String hexToken() {
        return hexToken(DEFAULT_BYTES);
    }

    public static String hexToken(int byteLength) {
        requireStrength(byteLength);
        return HexFormat.of().formatHex(randomBytes(byteLength));
    }

    /**
     * A numeric one-time code such as {@code 048213}. Uses
     * {@link SecureRandom#nextInt(int)}, which avoids modulo bias, so every
     * code is equally likely.
     */
    public static String numericCode(int digits) {
        if (digits < 4 || digits > 9) {
            throw new IllegalArgumentException("digits must be between 4 and 9");
        }
        int bound = (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", RANDOM.nextInt(bound));
    }

    private static void requireStrength(int byteLength) {
        if (byteLength < MIN_BYTES) {
            throw new IllegalArgumentException(
                    "tokens need at least " + MIN_BYTES + " bytes of entropy, got " + byteLength);
        }
    }
}
