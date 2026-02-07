package com.restaurant.shared.ratelimit;

/**
 * Excepción lanzada cuando se excede el límite de rate limiting. Debe ser manejada por el
 * GlobalExceptionHandler para retornar 429 Too Many Requests.
 */
public class RateLimitExceededException extends RuntimeException {

  private final long retryAfterSeconds;
  private final long remainingTokens;

    /**
     * Instantiates a new Rate limit exceeded exception.
     *
     * @param message           the message
     * @param retryAfterSeconds the retry after seconds
     */
    public RateLimitExceededException(String message, long retryAfterSeconds) {
    super(message);
    this.retryAfterSeconds = retryAfterSeconds;
    this.remainingTokens = 0;
  }

    /**
     * Instantiates a new Rate limit exceeded exception.
     *
     * @param message           the message
     * @param retryAfterSeconds the retry after seconds
     * @param remainingTokens   the remaining tokens
     */
    public RateLimitExceededException(String message, long retryAfterSeconds, long remainingTokens) {
    super(message);
    this.retryAfterSeconds = retryAfterSeconds;
    this.remainingTokens = remainingTokens;
  }

    /**
     * Gets retry after seconds.
     *
     * @return the retry after seconds
     */
    public long getRetryAfterSeconds() {
    return retryAfterSeconds;
  }

    /**
     * Gets remaining tokens.
     *
     * @return the remaining tokens
     */
    public long getRemainingTokens() {
    return remainingTokens;
  }
}
