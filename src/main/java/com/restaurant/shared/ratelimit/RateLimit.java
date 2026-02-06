package com.restaurant.shared.ratelimit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotación para aplicar rate limiting a métodos de controladores.
 *
 * <p>Ejemplo de uso:
 *
 * <pre>
 * {@literal @}PostMapping("/authenticate")
 * {@literal @}RateLimit(value = RateLimitType.AUTH, byUser = false)
 * public AuthResponse authenticate(@RequestBody AuthRequest request) {
 *     // ...
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {

  /** Tipo de rate limit a aplicar. Define la capacidad y duración de refill. */
  RateLimitType value() default RateLimitType.API;

  /**
   * Prefijo para la clave de rate limiting. Se concatena con el identificador (IP o User ID). Por
   * defecto usa el nombre del método.
   */
  String keyPrefix() default "";

  /**
   * Si true, el rate limit se aplica por usuario autenticado. Si false, se aplica por dirección IP.
   *
   * <p>Usar byUser=true para endpoints que requieren autenticación. Usar byUser=false para
   * endpoints públicos o de autenticación.
   */
  boolean byUser() default false;
}
