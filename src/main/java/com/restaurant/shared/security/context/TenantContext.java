package com.restaurant.shared.security.context;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;

/**
 * Holder for the current tenant identifier in a multi-tenant environment. Includes MDC integration
 * for log traceability.
 */
@Slf4j
public class TenantContext {

  private static final String COMPANY_ID_KEY = "companyId";
  private static final ThreadLocal<Long> CURRENT_COMPANY = new ThreadLocal<>();

  public static void setCurrentTenant(Long companyId) {
    if (companyId != null) {
      CURRENT_COMPANY.set(companyId);
      MDC.put(COMPANY_ID_KEY, companyId.toString());
    } else {
      CURRENT_COMPANY.remove();
      MDC.remove(COMPANY_ID_KEY);
    }
  }

  public static Long getCurrentTenant() {
    return CURRENT_COMPANY.get();
  }

  public static void clear() {
    CURRENT_COMPANY.remove();
    MDC.remove(COMPANY_ID_KEY);
  }
}
