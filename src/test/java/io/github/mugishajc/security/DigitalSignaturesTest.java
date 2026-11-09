package io.github.mugishajc.security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DigitalSignaturesTest {

    private final byte[] document = "release v1.4.0 sha256=9f2c...".getBytes(StandardCharsets.UTF_8);
    private final Map<SignatureScheme, KeyPair> keys = new EnumMap<>(SignatureScheme.class);

    @BeforeAll
    void generateKeys() {
        // RSA-3072 key generation is slow, so do it once per scheme.
        for (SignatureScheme scheme : SignatureScheme.values()) {
            keys.put(scheme, DigitalSignatures.generateKeyPair(scheme));
        }
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void signThenVerify(SignatureScheme scheme) {
        KeyPair pair = keys.get(scheme);
        byte[] sig = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        assertTrue(DigitalSignatures.verify(scheme, pair.getPublic(), document, sig));
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void modifiedDocumentFailsVerification(SignatureScheme scheme) {
        KeyPair pair = keys.get(scheme);
        byte[] sig = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        byte[] tampered = document.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(DigitalSignatures.verify(scheme, pair.getPublic(), tampered, sig));
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void modifiedSignatureFailsVerification(SignatureScheme scheme) {
        KeyPair pair = keys.get(scheme);
        byte[] sig = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        for (int i = 0; i < sig.length; i++) {
            byte[] tampered = sig.clone();
            tampered[i] ^= 0x01;
            assertFalse(DigitalSignatures.verify(scheme, pair.getPublic(), document, tampered), "byte " + i);
        }
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void garbageSignatureReturnsFalseInsteadOfThrowing(SignatureScheme scheme) {
        PublicKey pub = keys.get(scheme).getPublic();
        assertFalse(DigitalSignatures.verify(scheme, pub, document, new byte[0]));
        assertFalse(DigitalSignatures.verify(scheme, pub, document, new byte[] {0x30, 0x01, 0x00}));
        assertFalse(DigitalSignatures.verify(scheme, pub, document, null));
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void someoneElsesKeyDoesNotVerify(SignatureScheme scheme) {
        byte[] sig = DigitalSignatures.sign(scheme, keys.get(scheme).getPrivate(), document);
        KeyPair stranger = DigitalSignatures.generateKeyPair(scheme);
        assertFalse(DigitalSignatures.verify(scheme, stranger.getPublic(), document, sig));
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void signaturesAreRandomizedButBothVerify(SignatureScheme scheme) {
        // PSS uses a random salt and ECDSA a random nonce, so two signatures differ.
        KeyPair pair = keys.get(scheme);
        byte[] a = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        byte[] b = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        assertFalse(Arrays.equals(a, b));
        assertTrue(DigitalSignatures.verify(scheme, pair.getPublic(), document, a));
        assertTrue(DigitalSignatures.verify(scheme, pair.getPublic(), document, b));
    }

    @ParameterizedTest
    @EnumSource(SignatureScheme.class)
    void publicKeySurvivesEncoding(SignatureScheme scheme) {
        KeyPair pair = keys.get(scheme);
        String encoded = DigitalSignatures.encodePublicKey(pair.getPublic());
        PublicKey decoded = DigitalSignatures.decodePublicKey(scheme, encoded);
        assertEquals(pair.getPublic(), decoded);
        byte[] sig = DigitalSignatures.sign(scheme, pair.getPrivate(), document);
        assertTrue(DigitalSignatures.verify(scheme, decoded, document, sig));
    }

    @Test
    void mismatchedKeyTypeIsAProgrammingError() {
        KeyPair ec = keys.get(SignatureScheme.ECDSA_P256_SHA256);
        assertThrows(IllegalArgumentException.class,
                () -> DigitalSignatures.sign(SignatureScheme.RSA_PSS_SHA256, ec.getPrivate(), document));
    }

    @Test
    void invalidEncodedKeyIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> DigitalSignatures.decodePublicKey(SignatureScheme.ECDSA_P256_SHA256, "AAAA"));
        assertThrows(IllegalArgumentException.class,
                () -> DigitalSignatures.decodePublicKey(SignatureScheme.RSA_PSS_SHA256, "%%%"));
    }
}
