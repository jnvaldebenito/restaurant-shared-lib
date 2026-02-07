package com.restaurant.shared.event;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The type Notification event.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationEvent implements Serializable {
  private NotificationType type;
  private String targetId; // branchId for KITCHEN, sessionToken for CLIENT
  private Object payload;
  private String tenantId;

    /**
     * The enum Notification type.
     */
    public enum NotificationType {
        /**
         * Kitchen notification type.
         */
        KITCHEN,
        /**
         * Client notification type.
         */
        CLIENT
  }
}
