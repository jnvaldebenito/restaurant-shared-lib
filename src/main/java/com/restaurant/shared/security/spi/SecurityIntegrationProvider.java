package com.restaurant.shared.security.spi;

import org.springframework.security.core.userdetails.UserDetails;
import java.util.Optional;

/**
 * Service Provider Interface (SPI) for security integration.
 * Microservices must implement this to provide tenant resolution and user
 * loading.
 */
public interface SecurityIntegrationProvider {

    /**
     * Resolves a tenant ID based on the request domain.
     */
    Optional<Long> resolveTenantIdByDomain(String domain);

    /**
     * Loads user details by username.
     */
    UserDetails loadUserByUsername(String username);
}
