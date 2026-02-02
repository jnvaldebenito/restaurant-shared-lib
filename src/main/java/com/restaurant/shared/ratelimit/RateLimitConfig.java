package com.restaurant.shared.ratelimit;

import io.github.bucket4j.distributed.ExpirationStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.redisson.cas.RedissonBasedProxyManager;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RedissonClient;
import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de Rate Limiting con Bucket4j y Redis.
 * 
 * Usa Redisson para almacenamiento distribuido de buckets,
 * permitiendo rate limiting consistente en múltiples instancias.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "ratelimit.enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    @Value("${spring.data.redis.database:1}")
    private int redisDatabase;

    /**
     * Configura el ProxyManager de Bucket4j con Redisson.
     * 
     * El ProxyManager gestiona los buckets distribuidos en Redis.
     */
    @Bean
    public ProxyManager<String> proxyManager(RedissonClient redissonClient) {
        log.info("Configuring Bucket4j ProxyManager with Redis at {}:{}", redisHost, redisPort);

        // Cast to Redisson implementation to access CommandAsyncExecutor required by
        // Bucket4j 8.x
        return RedissonBasedProxyManager.builderFor(((org.redisson.Redisson) redissonClient).getCommandExecutor())
                .withExpirationStrategy(ExpirationStrategy.basedOnTimeForRefilling(Duration.ofHours(1)))
                .build();
    }

    /**
     * Personaliza la configuración de Redisson si es necesario.
     * 
     * Por defecto, Redisson se autoconfigura con las propiedades de Spring Boot.
     * Este customizer permite ajustes adicionales si se requieren.
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
