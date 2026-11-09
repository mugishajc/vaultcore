package io.github.mugishajc.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Password hashing with PBKDF2-HMAC-SHA256.
 *
 * <p>Each hash gets its own 16-byte random salt, so identical passwords produce
 * different hashes and precomputed rainbow tables are useless. The iteration
 * count makes each guess expensive; the default follows the OWASP Password
 * Storage Cheat Sheet recommendation of 600,000 for this PRF.
 *
 * <p>Hashes are stored as a self-describing string:
 * <pre>pbkdf2-sha256$600000$&lt;salt b64&gt;$&lt;hash b64&gt;</pre>
 * so the iteration count can be raised later without breaking existing users
 * (see {@link #needsRehash(String)}).
 *
 * <p>Passwords are accepted as {@code char[]} so callers can wipe them after use.
 */
public final class PasswordHasher {

    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int MIN_ITERATIONS = 100_000;

    private static final String PREFIX = "pbkdf2-sha256";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;

    private final int iterations;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < MIN_ITERATIONS) {
            throw new IllegalArgumentException("iterations must be at least " + MIN_ITERATIONS);
        }
        this.iterations = iterations;
    }

    public int iterations() {
        return iterations;
    }

    public String hash(char[] password) {
        requireUsable(password);
        byte[] salt = SecureTokens.randomBytes(SALT_BYTES);
        byte[] hash = derive(password, salt, iterations, HASH_BITS);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(hash);
    }

    /**
     * Checks a password against a stored hash. Malformed hashes simply fail to
     * verify rather than throwing, so a corrupted database row cannot be used
     * to distinguish accounts.
     */
    public boolean verify(char[] password, String stored) {
        if (password == null || stored == null) {
            return false;
        }
        Parsed parsed = Parsed.from(stored);
        if (parsed == null) {
            return false;
        }
        byte[] candidate = derive(password, parsed.salt, parsed.iterations, parsed.hash.length * 8);
        try {
            return ConstantTime.equals(candidate, parsed.hash);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }

    /** True if the stored hash was made with fewer iterations than this hasher uses. */
    public boolean needsRehash(String stored) {
        Parsed parsed = Parsed.from(stored);
        return parsed == null || parsed.iterations < iterations;
    }

    private static void requireUsable(char[] password) {
        Objects.requireNonNull(password, "password");
        if (password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int bits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("PBKDF2 is not available", e);
        } finally {
            spec.clearPassword();
        }
    }

    private record Parsed(int iterations, byte[] salt, byte[] hash) {

        static Parsed from(String stored) {
            if (stored == null) {
                return null;
            }
            String[] parts = stored.split("\\$");
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return null;
            }
            try {
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = Base64.getDecoder().decode(parts[2]);
                byte[] hash = Base64.getDecoder().decode(parts[3]);
                if (iterations < 1 || salt.length == 0 || hash.length == 0) {
                    return null;
                }
                return new Parsed(iterations, salt, hash);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }
}
