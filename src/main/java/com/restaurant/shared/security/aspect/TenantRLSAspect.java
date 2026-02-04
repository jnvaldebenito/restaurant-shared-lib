package com.restaurant.shared.security.aspect;

import com.restaurant.shared.security.context.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.restaurant.shared.security.dto.AccessUser;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class TenantRLSAspect {

    @PersistenceContext
    private EntityManager entityManager;

    private final com.restaurant.shared.security.context.RLSContextManager rlsContextManager;

    @Around("execution(* com.restaurant..service..*.*(..)) && !within(com.restaurant..service.SseNotificationService)")
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

        return rlsContextManager.runWithTenantContext(entityManager, companyId, joinPoint::proceed);
    }
}
