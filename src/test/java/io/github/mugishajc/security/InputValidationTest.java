package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InputValidationTest {

    @TempDir
    Path uploads;

    @Test
    void nonBlankIsTrimmedAndBounded() {
        assertEquals("Kigali", InputValidation.requireNonBlank("city", "  Kigali ", 20));
        assertThrows(ValidationException.class, () -> InputValidation.requireNonBlank("city", "   ", 20));
        assertThrows(ValidationException.class, () -> InputValidation.requireNonBlank("city", null, 20));
        assertThrows(ValidationException.class, () -> InputValidation.requireNonBlank("city", "x".repeat(21), 20));
    }

    @ParameterizedTest
    @ValueSource(strings = {"user_42", "order-2026", "A"})
    void acceptsIdentifiers(String value) {
        assertEquals(value, InputValidation.requireIdentifier("id", value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "1; DROP TABLE users", "<script>", "a b", "ü"})
    void rejectsIdentifiers(String value) {
        ValidationException e = assertThrows(ValidationException.class,
                () -> InputValidation.requireIdentifier("id", value));
        assertEquals("id", e.field());
    }

    @Test
    void emailIsNormalisedToLowerCase() {
        assertEquals("jean.claude@example.rw", InputValidation.requireEmail("email", " Jean.Claude@Example.RW "));
    }

    @ParameterizedTest
    @ValueSource(strings = {"plainaddress", "@example.com", "a@b", "a@@b.com", "a@b..com", "a b@c.com"})
    void rejectsMalformedEmails(String value) {
        assertThrows(ValidationException.class, () -> InputValidation.requireEmail("email", value));
    }

    @Test
    void emailPatternDoesNotBacktrackCatastrophically() {
        String hostile = "a".repeat(64) + "@" + "a.".repeat(5_000) + "!";
        assertTimeoutPreemptively(Duration.ofMillis(500),
                () -> assertThrows(ValidationException.class, () -> InputValidation.requireEmail("email", hostile)));
    }

    @Test
    void numbersMustParseAndBeInRange() {
        assertEquals(25, InputValidation.requireInRange("pageSize", "25", 1, 100));
        assertThrows(ValidationException.class, () -> InputValidation.requireInRange("pageSize", "0", 1, 100));
        assertThrows(ValidationException.class, () -> InputValidation.requireInRange("pageSize", "1e3", 1, 100));
        assertThrows(ValidationException.class, () -> InputValidation.requireInRange("pageSize", null, 1, 100));
    }

    @ParameterizedTest
    @ValueSource(strings = {"report.pdf", "invoice_2026-11.csv", "a"})
    void acceptsPlainFileNames(String value) {
        assertEquals(value, InputValidation.requireSafeFileName("file", value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"../secret", ".env", "dir/file.txt", "dir\\file.txt", "file\u0000.txt", ""})
    void rejectsDangerousFileNames(String value) {
        assertThrows(ValidationException.class, () -> InputValidation.requireSafeFileName("file", value));
    }

    @Test
    void resolvesPathsInsideBaseDirectory() {
        Path resolved = InputValidation.resolveWithin(uploads, "2026/11/photo.jpg");
        assertTrue(resolved.startsWith(uploads.toAbsolutePath().normalize()));
        assertEquals("photo.jpg", resolved.getFileName().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"../outside.txt", "a/../../outside.txt", "/etc/passwd", ".", "a/.."})
    void blocksPathTraversal(String value) {
        assertThrows(ValidationException.class, () -> InputValidation.resolveWithin(uploads, value));
    }

    @Test
    void siblingDirectoryWithSharedPrefixIsNotInside() {
        // "uploads-evil" starts with the same characters as "uploads" but is a different directory.
        String sibling = "../" + uploads.getFileName() + "-evil/x";
        assertThrows(ValidationException.class, () -> InputValidation.resolveWithin(uploads, sibling));
    }

    @Test
    void logSanitizerNeutralisesLineBreaks() {
        String forged = "bob\r\n2026-11-09 INFO admin logged in";
        String cleaned = InputValidation.sanitizeForLog(forged, 200);
        assertFalse(cleaned.contains("\n"));
        assertFalse(cleaned.contains("\r"));
        assertTrue(cleaned.startsWith("bob__"));
    }

    @Test
    void logSanitizerTruncates() {
        assertEquals("abc...", InputValidation.sanitizeForLog("abcdef", 3));
        assertEquals("null", InputValidation.sanitizeForLog(null, 3));
    }
}
