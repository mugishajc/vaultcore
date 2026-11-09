package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConstantTimeTest {

    @Test
    void comparesBytes() {
        assertTrue(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2, 3}));
        assertFalse(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2, 4}));
        assertFalse(ConstantTime.equals(new byte[] {1, 2, 3}, new byte[] {1, 2}));
    }

    @Test
    void comparesStrings() {
        assertTrue(ConstantTime.equals("s3cret", "s3cret"));
        assertFalse(ConstantTime.equals("s3cret", "s3creT"));
    }

    @Test
    void nullsNeverMatch() {
        assertFalse(ConstantTime.equals((byte[]) null, null));
        assertFalse(ConstantTime.equals((String) null, "x"));
        assertFalse(ConstantTime.equals("x", null));
    }
}
