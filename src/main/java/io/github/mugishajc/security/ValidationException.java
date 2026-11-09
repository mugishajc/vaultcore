package io.github.mugishajc.security;

/** Raised when untrusted input does not meet the expected format. */
public class ValidationException extends IllegalArgumentException {

    private final String field;

    public ValidationException(String field, String message) {
        super(field + ": " + message);
        this.field = field;
    }

    public String field() {
        return field;
    }
}
