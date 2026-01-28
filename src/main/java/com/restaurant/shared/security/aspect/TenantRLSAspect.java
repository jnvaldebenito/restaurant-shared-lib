package com.restaurant.shared.security.aspect;

import com.restaurant.shared.security.context.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    @Around("execution(* com.restaurant..service..*.*(..)) && !execution(* *.SseNotificationService.*(..))")
    public Object setTenantContext(ProceedingJoinPoint joinPoint) throws Throwable {
        Long companyId = TenantContext.getCurrentTenant();
        return rlsContextManager.runWithTenantContext(entityManager, companyId, joinPoint::proceed);
    }
}
