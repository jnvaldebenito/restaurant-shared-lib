package com.restaurant.shared.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationEvent implements Serializable {
    private NotificationType type;
    private String targetId; // branchId for KITCHEN, sessionToken for CLIENT
    private Object payload;
    private String tenantId;

    public enum NotificationType {
        KITCHEN,
        CLIENT
    }
}
