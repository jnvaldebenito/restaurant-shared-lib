package com.restaurant.shared.security.context;

import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

/**
 * Manages the Row Level Security (RLS) context in the database session. Ensures that tenant ID and
 * bypass flags are correctly set and RESTORED particularly in nested service calls.
 */
@Slf4j
@Component
public class RLSContextManager {

  private static final ThreadLocal<Boolean> systemContextActive =
      ThreadLocal.withInitial(() -> false);

    /**
     * Is system context boolean.
     *
     * @return the boolean
     */
    public boolean isSystemContext() {
    return systemContextActive.get();
  }

    /**
     * The interface Rls action.
     *
     * @param <T> the type parameter
     */
    @FunctionalInterface
  public interface RLSAction<T> {
        /**
         * Execute t.
         *
         * @return the t
         * @throws Throwable the throwable
         */
        T execute() throws Throwable;
  }

    /**
     * Executes an action with RLS bypassed (System Context). Restores previous tenant and bypass
     * settings after execution.
     *
     * @param <T>           the type parameter
     * @param entityManager the entity manager
     * @param action        the action
     * @return the t
     * @throws Throwable the throwable
     */
    public <T> T runInSystemContext(EntityManager entityManager, RLSAction<T> action)
      throws Throwable {
    Session session = entityManager.unwrap(Session.class);
    Boolean prevSystemContext = systemContextActive.get();
    systemContextActive.set(true);

    // We use a container to capture the OLD values from inside doReturningWork
    // but restoring must happen in its own doWork to ensure consistency.
    String[] context =
        session.doReturningWork(
            connection -> {
              try (var stmt = connection.createStatement()) {
                var rs =
                    stmt.executeQuery(
                        "SELECT current_setting('app.current_tenant_id', true), current_setting('app.bypass_rls', true)");
                rs.next();
                String prevTenant = rs.getString(1);
                String prevBypass = rs.getString(2);

                log.debug(
                    "Setting System Context. Previous tenant: {}, previous bypass: {}",
                    prevTenant,
                    prevBypass);

                stmt.execute("SELECT set_config('app.bypass_rls', 'on', true)");
                stmt.execute("SELECT set_config('app.current_tenant_id', '', true)");
                return new String[] {prevTenant, prevBypass};
              }
            });

    try {
      return action.execute();
    } finally {
      systemContextActive.set(prevSystemContext);
      session.doWork(
          connection -> {
            try (var stmt = connection.createStatement()) {
              stmt.execute(
                  "SELECT set_config('app.bypass_rls', " + formatValue(context[1]) + ", true)");
              stmt.execute(
                  "SELECT set_config('app.current_tenant_id', "
                      + formatValue(context[0])
                      + ", true)");
            }
          });
    }
  }

    /**
     * Executes an action with a specific tenant ID. Restores previous setting after execution.
     *
     * @param <T>           the type parameter
     * @param entityManager the entity manager
     * @param companyId     null to run in EMPTY context (RLS active, no data), NOT SYSTEM context. Use     runInSystemContext() explicitly if you need to bypass RLS.
     * @param action        the action
     * @return the t
     * @throws Throwable the throwable
     */
    public <T> T runWithTenantContext(
      EntityManager entityManager, Long companyId, RLSAction<T> action) throws Throwable {
    Session session = entityManager.unwrap(Session.class);
    Boolean prevSystemContext = systemContextActive.get();
    systemContextActive.set(false);

    // Capture previous state
    String[] prevState =
        session.doReturningWork(
            connection -> {
              try (var stmt = connection.createStatement()) {
                var rs =
                    stmt.executeQuery(
                        "SELECT current_setting('app.current_tenant_id', true), current_setting('app.bypass_rls', true)");
                rs.next();
                return new String[] {rs.getString(1), rs.getString(2)};
              }
            });

    // Set New Context
    session.doWork(
        connection -> {
          try (var stmt = connection.createStatement()) {
            // IMPORTANT: If companyId is null, we set tenant to empty string (RLS blocks
            // everything)
            // We ensure RLS bypass is OFF.
            String tenantVal = (companyId != null) ? "'" + companyId + "'" : "''";
            stmt.execute("SELECT set_config('app.current_tenant_id', " + tenantVal + ", true)");
            stmt.execute("SELECT set_config('app.bypass_rls', 'off', true)");
          }
        });

    try {
      return action.execute();
    } finally {
      systemContextActive.set(prevSystemContext);
      // Restore Previous Context
      session.doWork(
          connection -> {
            try (var stmt = connection.createStatement()) {
              stmt.execute(
                  "SELECT set_config('app.current_tenant_id', "
                      + formatValue(prevState[0])
                      + ", true)");
              stmt.execute(
                  "SELECT set_config('app.bypass_rls', " + formatValue(prevState[1]) + ", true)");
            }
          });
    }
  }

    /**
     * Set the RLS context directly (used by Aspects).  @param entityManager the entity manager
     *
     * @param companyId the company id
     */
    public void setTenantConfig(EntityManager entityManager, Long companyId) {
    Session session = entityManager.unwrap(Session.class);
    session.doWork(
        connection -> {
          try (var stmt = connection.createStatement()) {
            if (companyId != null) {
              stmt.execute("SELECT set_config('app.current_tenant_id', '" + companyId + "', true)");
            } else {
              stmt.execute("SELECT set_config('app.current_tenant_id', '', true)");
            }
          } catch (Exception e) {
            log.trace("Error setting tenant config {}: {}", companyId, e.getMessage());
          }
        });
  }

    /**
     * Clear the RLS context (used by Aspects).  @param entityManager the entity manager
     */
    public void clearTenantConfig(EntityManager entityManager) {
    Session session = entityManager.unwrap(Session.class);
    session.doWork(
        connection -> {
          try (var stmt = connection.createStatement()) {
            stmt.execute("SELECT set_config('app.current_tenant_id', '', true)");
          } catch (Exception e) {
            log.trace("Error clearing tenant config: {}", e.getMessage());
          }
        });
  }

  private String formatValue(String value) {
    if (value == null) return "NULL";
    return "'" + value.replace("'", "''") + "'";
  }
}
