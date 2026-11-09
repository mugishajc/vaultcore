package io.github.mugishajc.security;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Allow-list validation helpers for untrusted input.
 *
 * <p>The general rule: decide what valid input looks like and reject
 * everything else, rather than trying to strip out "bad" characters. Every
 * pattern here is anchored and has bounded repetition, so none of them can be
 * pushed into catastrophic regex backtracking.
 */
public final class InputValidation {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    // Deliberately simpler than RFC 5322: good enough to catch typos, and the
    // only real proof of an address is a confirmation email.
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\\.[A-Za-z0-9-]{1,63}){1,8}");
    private static final Pattern FILE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");

    private InputValidation() {
    }

    public static String requireNonBlank(String field, String value, int maxLength) {
        if (value == null || value.isBlank()) {
            throw new ValidationException(field, "is required");
        }
        if (value.length() > maxLength) {
            throw new ValidationException(field, "must be at most " + maxLength + " characters");
        }
        return value.strip();
    }

    /** Letters, digits, underscore and hyphen; 1 to 64 characters. */
    public static String requireIdentifier(String field, String value) {
        return requireMatch(field, value, IDENTIFIER, "may only contain letters, digits, '_' and '-'");
    }

    public static String requireEmail(String field, String value) {
        if (value == null || value.length() > 254) {
            throw new ValidationException(field, "is not a valid email address");
        }
        return requireMatch(field, value.strip(), EMAIL, "is not a valid email address").toLowerCase();
    }

    public static int requireInRange(String field, String value, int min, int max) {
        int parsed;
        try {
            parsed = Integer.parseInt(value == null ? "" : value.strip());
        } catch (NumberFormatException e) {
            throw new ValidationException(field, "must be a whole number");
        }
        if (parsed < min || parsed > max) {
            throw new ValidationException(field, "must be between " + min + " and " + max);
        }
        return parsed;
    }

    /**
     * Accepts a bare file name such as {@code report-2026.pdf}. Rejects path
     * separators, leading dots (hidden files, {@code ..}) and anything outside a
     * conservative character set.
     */
    public static String requireSafeFileName(String field, String value) {
        return requireMatch(field, value, FILE_NAME, "is not an allowed file name");
    }

    /**
     * Resolves a user-supplied relative path against {@code baseDir} and makes
     * sure the result stays inside it, which blocks {@code ../../etc/passwd}
     * style traversal. The check is done on normalised absolute paths, so it
     * also catches tricks like {@code uploads/../../secret}.
     *
     * <p>This does not follow symlinks. If attackers can create symlinks inside
     * {@code baseDir}, compare {@code toRealPath()} results instead.
     */
    public static Path resolveWithin(Path baseDir, String userPath) {
        if (userPath == null || userPath.isEmpty() || userPath.indexOf('\0') >= 0) {
            throw new ValidationException("path", "is not allowed");
        }
        Path base = baseDir.toAbsolutePath().normalize();
        Path resolved;
        try {
            resolved = base.resolve(userPath).normalize();
        } catch (InvalidPathException e) {
            throw new ValidationException("path", "is not allowed");
        }
        if (!resolved.startsWith(base) || resolved.equals(base)) {
            throw new ValidationException("path", "escapes the allowed directory");
        }
        return resolved;
    }

    /**
     * Makes a value safe to write to a single log line: control characters
     * (including CR and LF, used for log forging) become '_' and the result is
     * truncated. This is for logs only, not for HTML or SQL.
     */
    public static String sanitizeForLog(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFKC);
        String cleaned = CONTROL_CHARS.matcher(normalized).replaceAll("_");
        return cleaned.length() <= maxLength ? cleaned : cleaned.substring(0, maxLength) + "...";
    }

    private static String requireMatch(String field, String value, Pattern pattern, String message) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new ValidationException(field, message);
        }
        return value;
    }
}
