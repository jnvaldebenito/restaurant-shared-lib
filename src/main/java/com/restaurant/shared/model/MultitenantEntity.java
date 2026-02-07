package com.restaurant.shared.model;

import com.restaurant.shared.security.context.TenantContext;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * Base class for all entities that require tenant isolation via company_id. Automatically handles
 * the population of company_id from the TenantContext.
 */
@Data
@MappedSuperclass
@Slf4j
public abstract class MultitenantEntity {

  @Column(name = "company_id", nullable = false, updatable = false)
  private Long companyId;

    /**
     * Pre persist.
     */
    @PrePersist
  public void prePersist() {
    if (this.companyId == null) {
      Long currentCompanyId = TenantContext.getCurrentTenant();
      if (currentCompanyId != null) {
        this.companyId = currentCompanyId;
      } else {
        log.warn(
            "Attempting to persist multitenant entity {} without company context!",
            this.getClass().getSimpleName());
      }
    }
  }
}
