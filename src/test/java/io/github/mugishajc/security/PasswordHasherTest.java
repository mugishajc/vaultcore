package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherTest {

    // Use the minimum work factor to keep the suite fast.
    private final PasswordHasher hasher = new PasswordHasher(PasswordHasher.MIN_ITERATIONS);

    @Test
    void verifiesCorrectPassword() {
        String stored = hasher.hash("correct horse battery staple".toCharArray());
        assertTrue(hasher.verify("correct horse battery staple".toCharArray(), stored));
    }

    @Test
    void rejectsWrongPassword() {
        String stored = hasher.hash("hunter2".toCharArray());
        assertFalse(hasher.verify("hunter3".toCharArray(), stored));
        assertFalse(hasher.verify("Hunter2".toCharArray(), stored));
    }

    @Test
    void samePasswordGetsDifferentSalts() {
        String a = hasher.hash("password".toCharArray());
        String b = hasher.hash("password".toCharArray());
        assertNotEquals(a, b);
        assertTrue(hasher.verify("password".toCharArray(), a));
        assertTrue(hasher.verify("password".toCharArray(), b));
    }

    @Test
    void storedFormatIsSelfDescribing() {
        String stored = hasher.hash("pw".toCharArray());
        String[] parts = stored.split("\\$");
        assertEquals(4, parts.length);
        assertEquals("pbkdf2-sha256", parts[0]);
        assertEquals(String.valueOf(PasswordHasher.MIN_ITERATIONS), parts[1]);
    }

    @Test
    void tamperedHashDoesNotVerify() {
        String stored = hasher.hash("pw".toCharArray());
        char last = stored.charAt(stored.length() - 1);
        String tampered = stored.substring(0, stored.length() - 1) + (last == 'A' ? 'B' : 'A');
        assertFalse(hasher.verify("pw".toCharArray(), tampered));
    }

    @Test
    void malformedInputFailsClosed() {
        assertFalse(hasher.verify("pw".toCharArray(), null));
        assertFalse(hasher.verify("pw".toCharArray(), ""));
        assertFalse(hasher.verify("pw".toCharArray(), "md5$abc"));
        assertFalse(hasher.verify("pw".toCharArray(), "pbkdf2-sha256$notanumber$AAAA$AAAA"));
        assertFalse(hasher.verify("pw".toCharArray(), "pbkdf2-sha256$1000$!!$AAAA"));
        assertFalse(hasher.verify(null, hasher.hash("pw".toCharArray())));
    }

    @Test
    void detectsHashesThatNeedUpgrading() {
        String weak = hasher.hash("pw".toCharArray());
        PasswordHasher stronger = new PasswordHasher(PasswordHasher.MIN_ITERATIONS * 2);
        assertTrue(stronger.needsRehash(weak));
        assertFalse(hasher.needsRehash(weak));
        // Old hashes must still verify after the work factor is raised.
        assertTrue(stronger.verify("pw".toCharArray(), weak));
    }

    @Test
    void refusesLowWorkFactorsAndEmptyPasswords() {
        assertThrows(IllegalArgumentException.class, () -> new PasswordHasher(1_000));
        assertThrows(IllegalArgumentException.class, () -> hasher.hash(new char[0]));
    }

    @Test
    void defaultUsesOwaspIterationCount() {
        assertEquals(600_000, new PasswordHasher().iterations());
    }
}
