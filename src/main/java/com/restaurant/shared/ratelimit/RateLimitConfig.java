package com.restaurant.shared.ratelimit;

import java.time.Duration;

import org.redisson.api.RedissonClient;
import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.redisson.cas.RedissonBasedProxyManager;
import lombok.extern.slf4j.Slf4j;

/**
 * Configuración de Rate Limiting con Bucket4j y Redis.
 *
 * <p>
 * Usa Redisson para almacenamiento distribuido de buckets, permitiendo rate
 * limiting consistente
 * en múltiples instancias.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(prefix = "spring.ratelimit", name = "enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitConfig {

  /**
   * Configura el ProxyManager de Bucket4j con Redisson.
   *
   * <p>
   * El ProxyManager gestiona los buckets distribuidos en Redis.
   *
   * @param redissonClient the redisson client
   * @return the proxy manager
   */
  @Bean
  public ProxyManager<String> proxyManager(RedissonClient redissonClient) {
    log.info("Configuring Bucket4j ProxyManager with Redisson");

    // Cast to Redisson implementation to access CommandAsyncExecutor required by
    // Bucket4j 8.x
    return RedissonBasedProxyManager.builderFor(
        ((org.redisson.Redisson) redissonClient).getCommandExecutor())
        .withExpirationStrategy(
            ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(Duration.ofHours(1)))
        .build();
  }

  /**
   * Personaliza la configuración de Redisson si es necesario.
   *
   * <p>
   * Por defecto, Redisson se autoconfigura con las propiedades de Spring Boot.
   * Este customizer
   * permite ajustes adicionales si se requieren.
   *
   * @return the redisson auto configuration customizer
   */
  @Bean
  public RedissonAutoConfigurationCustomizer redissonCustomizer() {
    return config -> {
      // Configuración adicional de Redisson si es necesaria
      // Por ejemplo, timeouts, codec, etc.
      log.debug("Applying Redisson customizations for rate limiting");
    };
  }
}
