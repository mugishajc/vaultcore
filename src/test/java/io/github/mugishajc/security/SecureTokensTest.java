package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureTokensTest {

    @Test
    void urlSafeTokenHasExpectedLengthAndAlphabet() {
        String token = SecureTokens.urlSafeToken();
        assertEquals(43, token.length());
        assertTrue(token.matches("[A-Za-z0-9_-]+"), token);
    }

    @Test
    void hexTokenIsLowercaseHex() {
        String token = SecureTokens.hexToken();
        assertEquals(64, token.length());
        assertTrue(token.matches("[0-9a-f]+"), token);
    }

    @Test
    void tokensDoNotRepeat() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            assertTrue(seen.add(SecureTokens.urlSafeToken()), "duplicate token generated");
        }
    }

    @Test
    void rejectsWeakTokenLengths() {
        assertThrows(IllegalArgumentException.class, () -> SecureTokens.urlSafeToken(8));
        assertThrows(IllegalArgumentException.class, () -> SecureTokens.hexToken(15));
        assertThrows(IllegalArgumentException.class, () -> SecureTokens.randomBytes(0));
    }

    @Test
    void numericCodeIsZeroPaddedToRequestedDigits() {
        for (int i = 0; i < 1_000; i++) {
            String code = SecureTokens.numericCode(6);
            assertEquals(6, code.length());
            assertTrue(code.chars().allMatch(Character::isDigit), code);
        }
        assertThrows(IllegalArgumentException.class, () -> SecureTokens.numericCode(3));
        assertThrows(IllegalArgumentException.class, () -> SecureTokens.numericCode(10));
    }

    @Test
    void numericCodeUsesWholeRange() {
        // With 4 digits and 20k draws, every leading digit should show up.
        Set<Character> leading = new HashSet<>();
        for (int i = 0; i < 20_000; i++) {
            leading.add(SecureTokens.numericCode(4).charAt(0));
        }
        assertEquals(10, leading.size());
    }
}
