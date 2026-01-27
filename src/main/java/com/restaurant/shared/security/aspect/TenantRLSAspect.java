package com.restaurant.shared.security.aspect;

import com.restaurant.shared.security.context.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class TenantRLSAspect {

    @PersistenceContext
    private EntityManager entityManager;

    // Apply to any service method in any restaurant module, excluding
    // SseNotificationService
    @Around("execution(* com.restaurant..service..*.*(..)) && !execution(* *.SseNotificationService.*(..))")
    public Object setTenantContext(ProceedingJoinPoint joinPoint) throws Throwable {
        Long companyId = TenantContext.getCurrentTenant();
        boolean contextSet = false;

        if (companyId != null) {
            try {
                Session session = entityManager.unwrap(Session.class);
                session.doWork(connection -> {
                    try (var stmt = connection.createStatement()) {
                        stmt.execute("SELECT set_config('app.current_tenant_id', '" + companyId + "', false)");
                    }
                });
                contextSet = true;
            } catch (Exception e) {
                // Log but don't fail, maybe not a transaction or no DB access needed
                log.trace("Could not set RLS context for company {}: {}", companyId, e.getMessage());
            }
        }

        try {
            return joinPoint.proceed();
        } finally {
            if (contextSet) {
                try {
                    Session session = entityManager.unwrap(Session.class);
                    session.doWork(connection -> {
                        try (var stmt = connection.createStatement()) {
                            stmt.execute("SELECT set_config('app.current_tenant_id', NULL, false)");
                        }
                    });
                } catch (Exception e) {
                    log.error("CRITICAL: Failed to clean up RLS context for company {}", companyId, e);
                }
            }
        }
    }
}
