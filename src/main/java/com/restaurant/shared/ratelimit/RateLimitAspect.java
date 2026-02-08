package com.restaurant.shared.ratelimit;

import java.util.function.Supplier;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Aspect que intercepta métodos anotados con @RateLimit y aplica rate limiting.
 *
 * <p>
 * Usa Bucket4j con Redis para rate limiting distribuido. Soporta rate limiting
 * por IP o por
 * usuario autenticado.
 */
@Slf4j
@Aspect
@Component
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(prefix = "spring.ratelimit", name = "enabled", havingValue = "true", matchIfMissing = true)
@org.springframework.boot.autoconfigure.condition.ConditionalOnBean(ProxyManager.class)
@RequiredArgsConstructor
public class RateLimitAspect {

  private final ClientIpResolver clientIpResolver;
  private final ProxyManager<String> proxyManager;

  /**
   * Intercepta métodos anotados con @RateLimit. @param pjp the pjp
   *
   * @param rateLimit the rate limit
   * @return the object
   * @throws Throwable the throwable
   */
  @Around("@annotation(rateLimit)")
  public Object checkRateLimit(ProceedingJoinPoint pjp, RateLimit rateLimit) throws Throwable {
    HttpServletRequest request = getCurrentRequest();
    if (request == null) {
      log.warn("No HttpServletRequest found, skipping rate limit check");
      return pjp.proceed();
    }

    // Construir clave única para el bucket
    String key = buildRateLimitKey(request, rateLimit, pjp);

    // Obtener o crear bucket
    Bucket bucket = getBucket(key, rateLimit.value());

    // Intentar consumir un token
    ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

    if (probe.isConsumed()) {
      // Request permitido
      addRateLimitHeaders(probe, rateLimit.value());
      log.debug(
          "Rate limit check passed for key: {}, remaining: {}", key, probe.getRemainingTokens());
      return pjp.proceed();
    } else {
      // Rate limit excedido
      long retryAfterSeconds = probe.getNanosToWaitForRefill() / 1_000_000_000;
      addRateLimitHeaders(probe, rateLimit.value());

      log.warn("Rate limit exceeded for key: {}, retry after: {} seconds", key, retryAfterSeconds);

      throw new RateLimitExceededException(
          "Rate limit exceeded. Try again in " + retryAfterSeconds + " seconds",
          retryAfterSeconds,
          probe.getRemainingTokens());
    }
  }

  /**
   * Construye la clave única para el bucket de rate limiting.
   *
   * <p>
   * Formato: "ratelimit:{prefix}:{identifier}" - prefix: keyPrefix de la
   * anotación o nombre del
   * método - identifier: IP del cliente o User ID
   */
  private String buildRateLimitKey(
      HttpServletRequest request, RateLimit rateLimit, ProceedingJoinPoint pjp) {
    String prefix = rateLimit.keyPrefix();

    // Si no hay prefix, usar nombre del método
    if (prefix.isEmpty()) {
      MethodSignature signature = (MethodSignature) pjp.getSignature();
      prefix = signature.getMethod().getName();
    }

    // Determinar identificador (IP o User ID)
    String identifier;
    if (rateLimit.byUser()) {
      identifier = getCurrentUserId();
      if (identifier == null || identifier.equals("anonymous")) {
        // Fallback a IP si no hay usuario autenticado
        identifier = clientIpResolver.resolveClientIp(request);
        log.debug("No authenticated user, falling back to IP: {}", identifier);
      }
    } else {
      identifier = clientIpResolver.resolveClientIp(request);
    }

    return String.format("ratelimit:%s:%s", prefix, identifier);
  }

  /** Obtiene o crea un bucket para la clave especificada. */
  private Bucket getBucket(String key, RateLimitType rateLimitType) {
    Supplier<BucketConfiguration> configSupplier = () -> BucketConfiguration.builder()
        .addLimit(
            limit -> limit
                .capacity(rateLimitType.getCapacity())
                .refillGreedy(
                    rateLimitType.getCapacity(), rateLimitType.getRefillDuration()))
        .build();

    return proxyManager.builder().build(key, configSupplier);
  }

  /**
   * Agrega headers de rate limiting a la respuesta.
   *
   * <p>
   * Headers estándar: - X-RateLimit-Limit: Límite total - X-RateLimit-Remaining:
   * Tokens
   * restantes - X-RateLimit-Reset: Timestamp de reset - Retry-After: Segundos
   * para reintentar (solo
   * si excedido)
   */
  private void addRateLimitHeaders(ConsumptionProbe probe, RateLimitType rateLimitType) {
    HttpServletResponse response = getCurrentResponse();
    if (response == null) {
      return;
    }

    long limit = rateLimitType.getCapacity();
    long remaining = probe.getRemainingTokens();
    long resetTimestamp = System.currentTimeMillis() / 1000 + rateLimitType.getRefillDuration().getSeconds();

    response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
    response.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));
    response.setHeader("X-RateLimit-Reset", String.valueOf(resetTimestamp));

    // Agregar Retry-After solo si el límite fue excedido
    if (!probe.isConsumed()) {
      long retryAfter = probe.getNanosToWaitForRefill() / 1_000_000_000;
      response.setHeader("Retry-After", String.valueOf(retryAfter));
    }
  }

  /** Obtiene el ID del usuario autenticado actual. */
  private String getCurrentUserId() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication == null || !authentication.isAuthenticated()) {
      return "anonymous";
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof String) {
      return (String) principal;
    }

    // Si el principal tiene un método getId() o getUsername()
    try {
      return principal.getClass().getMethod("getUsername").invoke(principal).toString();
    } catch (Exception e) {
      return authentication.getName();
    }
  }

  /** Obtiene el HttpServletRequest actual. */
  private HttpServletRequest getCurrentRequest() {
    ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
    return attributes != null ? attributes.getRequest() : null;
  }

  /** Obtiene el HttpServletResponse actual. */
  private HttpServletResponse getCurrentResponse() {
    ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
    return attributes != null ? attributes.getResponse() : null;
  }
}
