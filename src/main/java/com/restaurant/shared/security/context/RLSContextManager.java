package com.restaurant.shared.security.context;

import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

/**
 * Manages the Row Level Security (RLS) context in the database session.
 * Ensures that tenant ID and bypass flags are correctly set and RESTORED
 * particularly in nested service calls.
 */
@Slf4j
@Component
public class RLSContextManager {

    @FunctionalInterface
    public interface RLSAction<T> {
        T execute() throws Throwable;
    }

    /**
     * Executes an action with RLS bypassed (System Context).
     * Restores previous tenant and bypass settings after execution.
     */
    public <T> T runInSystemContext(EntityManager entityManager, RLSAction<T> action) throws Throwable {
        Session session = entityManager.unwrap(Session.class);

        // We use a container to capture the OLD values from inside doReturningWork
        // but restoring must happen in its own doWork to ensure consistency.
        String[] context = session.doReturningWork(connection -> {
            try (var stmt = connection.createStatement()) {
                var rs = stmt.executeQuery(
                        "SELECT current_setting('app.current_tenant_id', true), current_setting('app.bypass_rls', true)");
                rs.next();
                String prevTenant = rs.getString(1);
                String prevBypass = rs.getString(2);

                stmt.execute("SELECT set_config('app.bypass_rls', 'on', false)");
                stmt.execute("SELECT set_config('app.current_tenant_id', '', false)");
                return new String[] { prevTenant, prevBypass };
            }
        });

        try {
            return action.execute();
        } finally {
            session.doWork(connection -> {
                try (var stmt = connection.createStatement()) {
                    stmt.execute("SELECT set_config('app.bypass_rls', " + formatValue(context[1]) + ", false)");
                    stmt.execute("SELECT set_config('app.current_tenant_id', " + formatValue(context[0]) + ", false)");
                }
            });
        }
    }

    /**
     * Executes an action with a specific tenant ID.
     * Restores previous setting after execution.
     */
    public <T> T runWithTenantContext(EntityManager entityManager, Long companyId, RLSAction<T> action)
            throws Throwable {
        if (companyId == null) {
            return runInSystemContext(entityManager, action);
        }

        Session session = entityManager.unwrap(Session.class);

        String prevTenant = session.doReturningWork(connection -> {
            try (var stmt = connection.createStatement()) {
                var rs = stmt.executeQuery("SELECT current_setting('app.current_tenant_id', true)");
                rs.next();
                String old = rs.getString(1);
                stmt.execute("SELECT set_config('app.current_tenant_id', '" + companyId + "', false)");
                return old;
            }
        });

        try {
            return action.execute();
        } finally {
            session.doWork(connection -> {
                try (var stmt = connection.createStatement()) {
                    stmt.execute("SELECT set_config('app.current_tenant_id', " + formatValue(prevTenant) + ", false)");
                }
            });
        }
    }

    /**
     * Set the RLS context directly (used by Aspects).
     */
    public void setTenantConfig(EntityManager entityManager, Long companyId) {
        Session session = entityManager.unwrap(Session.class);
        session.doWork(connection -> {
            try (var stmt = connection.createStatement()) {
                if (companyId != null) {
                    stmt.execute("SELECT set_config('app.current_tenant_id', '" + companyId + "', false)");
                } else {
                    stmt.execute("SELECT set_config('app.current_tenant_id', '', false)");
                }
            } catch (Exception e) {
                log.trace("Error setting tenant config {}: {}", companyId, e.getMessage());
            }
        });
    }

    /**
     * Clear the RLS context (used by Aspects).
     */
    public void clearTenantConfig(EntityManager entityManager) {
        Session session = entityManager.unwrap(Session.class);
        session.doWork(connection -> {
            try (var stmt = connection.createStatement()) {
                stmt.execute("SELECT set_config('app.current_tenant_id', '', false)");
            } catch (Exception e) {
                log.trace("Error clearing tenant config: {}", e.getMessage());
            }
        });
    }

    private String formatValue(String value) {
        return (value == null || value.isEmpty()) ? "NULL" : "'" + value + "'";
    }
}
