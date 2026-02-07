package com.restaurant.shared.security.aspect;

import com.restaurant.shared.security.context.TenantContext;
import com.restaurant.shared.security.dto.AccessUser;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.PersistenceException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class TenantRLSAspect {

  @PersistenceContext private EntityManager entityManager;

  private final com.restaurant.shared.security.context.RLSContextManager rlsContextManager;

  @Around(
      "(execution(* com.restaurant..service..*.*(..)) || execution(* com.restaurant..controller..*.*(..))) && !within(com.restaurant..service.SseNotificationService)")
  public Object setTenantContext(ProceedingJoinPoint joinPoint) throws Throwable {
    if (rlsContextManager.isSystemContext()) {
      return joinPoint.proceed();
    }

    Long companyId = TenantContext.getCurrentTenant();

    // Robustness: If TenantContext is missing, recover from SecurityContext
    if (companyId == null) {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null && auth.getPrincipal() instanceof AccessUser user) {
        companyId = user.getCompanyId();
        if (companyId != null) {
          log.debug("Restored TenantContext from SecurityContext for user: {}", user.getUsername());
          TenantContext.setCurrentTenant(companyId);
        }
      }
    }

    return rlsContextManager.runWithTenantContext(
        entityManager,
        companyId,
        () -> {
          Object result = joinPoint.proceed();
          // Force flush to ensure DB ops happen while RLS context is active
          // This prevents "Row was updated or deleted by another transaction" errors
          // caused by the context being restored before the transaction commit/flush.
          if (TransactionSynchronizationManager.isActualTransactionActive()) {
            try {
              entityManager.flush();
            } catch (PersistenceException e) {
              log.debug(
                  "No flush performed: transaction no longer active or required. Phase: {}",
                  TransactionSynchronizationManager.isActualTransactionActive());
            }
          }
          return result;
        });
  }
}
