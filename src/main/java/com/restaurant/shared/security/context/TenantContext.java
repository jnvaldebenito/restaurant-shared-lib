package com.restaurant.shared.security.context;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;

/**
 * Holder for the current tenant identifier in a multi-tenant environment.
 * Includes MDC integration for log traceability.
 */
@Slf4j
public class TenantContext {

    private static final String TENANT_ID_KEY = "tenantId";
    private static final ThreadLocal<Long> CURRENT_TENANT = new ThreadLocal<>();

    public static void setCurrentTenant(Long tenantId) {
        CURRENT_TENANT.set(tenantId);
        if (tenantId != null) {
            MDC.put(TENANT_ID_KEY, tenantId.toString());
        } else {
            MDC.remove(TENANT_ID_KEY);
        }
    }

    public static Long getCurrentTenant() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
        MDC.remove(TENANT_ID_KEY);
    }
}
