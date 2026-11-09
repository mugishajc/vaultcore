package io.github.mugishajc.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacSignerTest {

    private final HmacSigner signer = HmacSigner.withNewKey();
    private final byte[] message = "{\"event\":\"invoice.paid\",\"id\":981}".getBytes(StandardCharsets.UTF_8);

    @Test
    void signAndVerify() {
        byte[] tag = signer.sign(message);
        assertTrue(signer.verify(message, tag));
    }

    @Test
    void anyChangeToMessageIsDetected() {
        byte[] tag = signer.sign(message);
        for (int i = 0; i < message.length; i++) {
            byte[] tampered = message.clone();
            tampered[i] ^= 0x20;
            assertFalse(signer.verify(tampered, tag), "byte " + i);
        }
    }

    @Test
    void anyChangeToTagIsDetected() {
        byte[] tag = signer.sign(message);
        for (int i = 0; i < tag.length; i++) {
            byte[] tampered = tag.clone();
            tampered[i] ^= 0x01;
            assertFalse(signer.verify(message, tampered), "byte " + i);
        }
        assertFalse(signer.verify(message, new byte[0]));
        assertFalse(signer.verify(message, null));
    }

    @Test
    void differentKeyDoesNotVerify() {
        byte[] tag = signer.sign(message);
        assertFalse(HmacSigner.withNewKey().verify(message, tag));
    }

    @Test
    void rejectsShortKeys() {
        assertThrows(IllegalArgumentException.class, () -> new HmacSigner(new byte[16]));
    }

    @Test
    void tokenRoundTrip() {
        String token = signer.signToToken("user=42;exp=1767225600");
        assertEquals("user=42;exp=1767225600", signer.verifyToken(token));
    }

    @Test
    void tokenWithEditedPayloadIsRejected() {
        String token = signer.signToToken("user=42;role=user");
        String signature = token.substring(token.indexOf('.'));
        String forgedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("user=42;role=admin".getBytes(StandardCharsets.UTF_8));
        assertThrows(IntegrityException.class, () -> signer.verifyToken(forgedBody + signature));
    }

    @Test
    void malformedTokensAreRejected() {
        assertThrows(IntegrityException.class, () -> signer.verifyToken(null));
        assertThrows(IntegrityException.class, () -> signer.verifyToken("no-dot"));
        assertThrows(IntegrityException.class, () -> signer.verifyToken(".abc"));
        assertThrows(IntegrityException.class, () -> signer.verifyToken("abc."));
        assertThrows(IntegrityException.class, () -> signer.verifyToken("a.b.c"));
        assertThrows(IntegrityException.class, () -> signer.verifyToken("***.***"));
    }

    @Test
    void knownAnswerFromRfc4231TestCase1() {
        // RFC 4231 section 4.2 uses a 20-byte key of 0x0b. HMAC zero-pads short keys
        // to the block size, so the same bytes followed by zeros (to satisfy our
        // 32-byte minimum) must produce the published tag.
        byte[] key = new byte[32];
        Arrays.fill(key, 0, 20, (byte) 0x0b);
        byte[] tag = new HmacSigner(key).sign("Hi There".getBytes(StandardCharsets.US_ASCII));
        assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                HexFormat.of().formatHex(tag));
    }
}
