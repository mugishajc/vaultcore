package io.github.mugishajc.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Comparisons that take the same time regardless of where inputs differ.
 *
 * <p>{@link String#equals(Object)} and {@link java.util.Arrays#equals(byte[], byte[])}
 * return at the first mismatching byte. When comparing secrets such as MACs or
 * API keys, that early exit leaks how many leading bytes were correct, and an
 * attacker can recover the secret one byte at a time by timing responses.
 */
public final class ConstantTime {

    private ConstantTime() {
    }

    /** Null-safe, length-leaking-only comparison of two byte arrays. */
    public static boolean equals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        // MessageDigest.isEqual has been constant-time since Java 6u17.
        return MessageDigest.isEqual(a, b);
    }

    public static boolean equals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return equals(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
