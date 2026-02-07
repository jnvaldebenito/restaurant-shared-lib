package com.restaurant.shared.ratelimit;

import java.time.Duration;

/**
 * Tipos de rate limiting predefinidos para diferentes categorías de endpoints.
 *
 * <p>Cada tipo define: - capacity: Número máximo de requests permitidos - refillDuration: Ventana
 * de tiempo para refill
 */
public enum RateLimitType {

    /**
     * Para endpoints de autenticación. Límite: 5 requests por minuto Previene: Ataques de fuerza
     * bruta
     */
    AUTH(5, Duration.ofMinutes(1)),

    /**
     * Para endpoints de API generales. Límite: 60 requests por minuto Previene: Abuso de API
     */
    API(60, Duration.ofMinutes(1)),

    /**
     * Para endpoints públicos (sin autenticación). Límite: 30 requests por minuto Previene: Scraping
     */
    PUBLIC(30, Duration.ofMinutes(1)),

    /**
     * Para endpoints de pago. Límite: 10 requests por minuto Previene: Fraude y abuso
     */
    PAYMENT(10, Duration.ofMinutes(1)),

    /**
     * Para registro de nuevos usuarios. Límite: 3 requests por hora Previene: Spam y registro masivo
     */
    REGISTRATION(3, Duration.ofHours(1));

  private final long capacity;
  private final Duration refillDuration;

  RateLimitType(long capacity, Duration refillDuration) {
    this.capacity = capacity;
    this.refillDuration = refillDuration;
  }

    /**
     * Gets capacity.
     *
     * @return the capacity
     */
    public long getCapacity() {
    return capacity;
  }

    /**
     * Gets refill duration.
     *
     * @return the refill duration
     */
    public Duration getRefillDuration() {
    return refillDuration;
  }
}
