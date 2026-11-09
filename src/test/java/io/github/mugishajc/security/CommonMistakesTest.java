package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * These tests use the raw JCA to show what goes wrong with the patterns this
 * library avoids. They pass because the attacks work.
 */
class CommonMistakesTest {

    private final SecretKey key = AesGcm.generateKey();

    @Test
    void ecbLeaksRepeatedPlaintextBlocks() throws Exception {
        // Two identical 16-byte blocks, as you get with structured data or images.
        byte[] plaintext = "ATTACK AT DAWN!!ATTACK AT DAWN!!".getBytes(StandardCharsets.US_ASCII);

        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        ecb.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = ecb.doFinal(plaintext);

        // An eavesdropper can see the two blocks are equal without the key.
        assertArrayEquals(Arrays.copyOfRange(ct, 0, 16), Arrays.copyOfRange(ct, 16, 32));
    }

    @Test
    void gcmDoesNotLeakRepeatedBlocks() {
        byte[] plaintext = "ATTACK AT DAWN!!ATTACK AT DAWN!!".getBytes(StandardCharsets.US_ASCII);
        byte[] sealed = AesGcm.withKey(key).encrypt(plaintext);
        int start = AesGcm.IV_BYTES;
        assertFalse(Arrays.equals(
                Arrays.copyOfRange(sealed, start, start + 16),
                Arrays.copyOfRange(sealed, start + 16, start + 32)));
    }

    @Test
    void reusingAGcmIvLeaksTheXorOfPlaintexts() throws Exception {
        byte[] staticIv = new byte[AesGcm.IV_BYTES]; // the classic bug: an all-zero or hard-coded IV
        byte[] p1 = "salary=1200000RWF".getBytes(StandardCharsets.US_ASCII);
        byte[] p2 = "salary=0450000RWF".getBytes(StandardCharsets.US_ASCII);

        byte[] c1 = encryptWithIv(staticIv, p1);
        byte[] c2 = encryptWithIv(staticIv, p2);

        // GCM is a stream cipher underneath: same key + IV means same keystream,
        // so c1 XOR c2 == p1 XOR p2. Knowing one plaintext reveals the other.
        byte[] recovered = new byte[p1.length];
        for (int i = 0; i < p1.length; i++) {
            recovered[i] = (byte) (c1[i] ^ c2[i] ^ p1[i]);
        }
        assertArrayEquals(p2, recovered);
    }

    @Test
    void earlyExitComparisonRevealsMatchingPrefixLength() {
        // Not a timing measurement (too noisy for a unit test), but it shows the
        // shape of the problem: a naive loop does less work the earlier it fails.
        byte[] secret = "f3a9c1d07be2".getBytes(StandardCharsets.US_ASCII);
        assertEquals(1, naiveCompareSteps(secret, "000000000000".getBytes(StandardCharsets.US_ASCII)));
        // Six correct leading bytes means the loop only bails out on the seventh.
        assertEquals(7, naiveCompareSteps(secret, "f3a9c1000000".getBytes(StandardCharsets.US_ASCII)));
    }

    private byte[] encryptWithIv(byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(AesGcm.TAG_BITS, iv));
        return cipher.doFinal(plaintext);
    }

    private static int naiveCompareSteps(byte[] a, byte[] b) {
        int steps = 0;
        for (int i = 0; i < a.length; i++) {
            steps++;
            if (a[i] != b[i]) {
                return steps;
            }
        }
        return steps;
    }
}
