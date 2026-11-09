package io.github.mugishajc.security;

/**
 * Thrown when ciphertext or a signed message fails its integrity check.
 * Callers should treat the input as hostile and must not use any part of it.
 */
public class IntegrityException extends CryptoException {

    public IntegrityException(String message) {
        super(message);
    }

    public IntegrityException(String message, Throwable cause) {
        super(message, cause);
    }
}
