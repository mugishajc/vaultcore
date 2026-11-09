package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmTest {

    private final AesGcm aes = AesGcm.withNewKey();
    private final byte[] plaintext = "transfer 5000 RWF to account 42".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip() {
        byte[] sealed = aes.encrypt(plaintext);
        assertArrayEquals(plaintext, aes.decrypt(sealed));
    }

    @Test
    void roundTripWithAssociatedData() {
        byte[] aad = "user:17".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = aes.encrypt(plaintext, aad);
        assertArrayEquals(plaintext, aes.decrypt(sealed, aad));
    }

    @Test
    void emptyPlaintextStillAuthenticated() {
        byte[] sealed = aes.encrypt(new byte[0]);
        assertEquals(AesGcm.IV_BYTES + AesGcm.TAG_BITS / 8, sealed.length);
        assertArrayEquals(new byte[0], aes.decrypt(sealed));
    }

    @Test
    void sameInputEncryptsDifferentlyEachTime() {
        byte[] first = aes.encrypt(plaintext);
        byte[] second = aes.encrypt(plaintext);
        assertFalse(Arrays.equals(first, second), "ciphertexts must differ");
        assertFalse(Arrays.equals(
                Arrays.copyOf(first, AesGcm.IV_BYTES),
                Arrays.copyOf(second, AesGcm.IV_BYTES)), "IVs must not repeat");
    }

    @Test
    void flippingAnyCiphertextBitIsDetected() {
        byte[] sealed = aes.encrypt(plaintext);
        for (int i = 0; i < sealed.length; i++) {
            byte[] tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assertThrows(IntegrityException.class, () -> aes.decrypt(tampered), "byte " + i);
        }
    }

    @Test
    void truncatedMessageIsRejected() {
        byte[] sealed = aes.encrypt(plaintext);
        assertThrows(IntegrityException.class, () -> aes.decrypt(Arrays.copyOf(sealed, sealed.length - 1)));
        assertThrows(IntegrityException.class, () -> aes.decrypt(new byte[5]));
    }

    @Test
    void wrongAssociatedDataIsRejected() {
        byte[] sealed = aes.encrypt(plaintext, "user:17".getBytes(StandardCharsets.UTF_8));
        assertThrows(IntegrityException.class,
                () -> aes.decrypt(sealed, "user:18".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void wrongKeyIsRejected() {
        byte[] sealed = aes.encrypt(plaintext);
        AesGcm other = AesGcm.withNewKey();
        assertThrows(IntegrityException.class, () -> other.decrypt(sealed));
    }

    @Test
    void keyCanBeRestoredFromRawBytes() {
        byte[] raw = aes.key().getEncoded();
        AesGcm restored = AesGcm.withKey(raw);
        assertArrayEquals(plaintext, restored.decrypt(aes.encrypt(plaintext)));
    }

    @Test
    void rejectsKeysThatAreNot256Bits() {
        assertThrows(IllegalArgumentException.class, () -> AesGcm.withKey(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> AesGcm.withKey(new byte[31]));
    }

    @Test
    void base64HelpersRoundTripUnicode() {
        String secret = "Murakoze cyane - ndakwemera ✓";
        String encoded = aes.encryptToBase64(secret);
        assertNotEquals(secret, encoded);
        assertEquals(secret, aes.decryptFromBase64(encoded));
    }

    @Test
    void garbageBase64IsAnIntegrityFailure() {
        assertThrows(IntegrityException.class, () -> aes.decryptFromBase64("not base64 !!"));
    }
}
