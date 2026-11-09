package io.github.mugishajc.security;

/**
 * Unchecked wrapper for JCA failures that indicate a programming or
 * configuration error (missing algorithm, bad key size, and so on).
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
