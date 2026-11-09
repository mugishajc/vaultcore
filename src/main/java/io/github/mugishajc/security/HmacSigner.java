package io.github.mugishajc.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

/**
 * HMAC-SHA256 message authentication.
 *
 * <p>Use this when both sides share a secret, e.g. signing webhook payloads or
 * stateless "remember me" cookies. A plain hash such as {@code sha256(secret + message)}
 * is not a MAC: it is open to length-extension attacks. HMAC is not.
 *
 * <p>Tags are always compared in constant time.
 */
public final class HmacSigner {

    public static final int MIN_KEY_BYTES = 32;
    private static final String ALGORITHM = "HmacSHA256";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private final SecretKeySpec key;

    public HmacSigner(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length < MIN_KEY_BYTES) {
            throw new IllegalArgumentException("HMAC-SHA256 key should be at least " + MIN_KEY_BYTES + " bytes");
        }
        this.key = new SecretKeySpec(key.clone(), ALGORITHM);
    }

    public static HmacSigner withNewKey() {
        return new HmacSigner(SecureTokens.randomBytes(MIN_KEY_BYTES));
    }

    public byte[] sign(byte[] message) {
        Objects.requireNonNull(message, "message");
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HMAC computation failed", e);
        }
    }

    public boolean verify(byte[] message, byte[] tag) {
        if (message == null || tag == null) {
            return false;
        }
        return ConstantTime.equals(sign(message), tag);
    }

    /**
     * Produces {@code base64url(payload) + "." + base64url(tag)}. The payload is
     * readable by anyone; this proves who issued it, it does not hide it.
     */
    public String signToToken(String payload) {
        Objects.requireNonNull(payload, "payload");
        byte[] body = payload.getBytes(StandardCharsets.UTF_8);
        return B64URL.encodeToString(body) + "." + B64URL.encodeToString(sign(body));
    }

    /**
     * Verifies a token from {@link #signToToken(String)} and returns its payload.
     *
     * @throws IntegrityException if the token is malformed or the signature does not match
     */
    public String verifyToken(String token) {
        if (token == null) {
            throw new IntegrityException("token is missing");
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.') || dot == token.length() - 1) {
            throw new IntegrityException("token is malformed");
        }
        byte[] body;
        byte[] tag;
        try {
            body = B64URL_DECODER.decode(token.substring(0, dot));
            tag = B64URL_DECODER.decode(token.substring(dot + 1));
        } catch (IllegalArgumentException e) {
            throw new IntegrityException("token is not valid Base64", e);
        }
        if (!verify(body, tag)) {
            throw new IntegrityException("token signature does not match");
        }
        return new String(body, StandardCharsets.UTF_8);
    }
}
