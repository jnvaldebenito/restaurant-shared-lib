package com.restaurant.shared.dto;

import lombok.Data;
import java.io.Serializable;

@Data
public class WebPushSubscriptionDTO implements Serializable {
    private String endpoint;
    private String p256dh;
    private String auth;
    private String sessionToken;
}
