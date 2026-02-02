package com.restaurant.shared.ratelimit;

/**
 * Excepción lanzada cuando se excede el límite de rate limiting.
 * Debe ser manejada por el GlobalExceptionHandler para retornar 429 Too Many
 * Requests.
 */
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;
    private final long remainingTokens;

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
        this.remainingTokens = 0;
    }

    public RateLimitExceededException(String message, long retryAfterSeconds, long remainingTokens) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
        this.remainingTokens = remainingTokens;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

    public long getRemainingTokens() {
        return remainingTokens;
    }
}
