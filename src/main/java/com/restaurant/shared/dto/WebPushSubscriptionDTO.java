package com.restaurant.shared.dto;

import com.restaurant.shared.validation.SafeString;
import java.io.Serializable;
import lombok.Data;

@Data
public class WebPushSubscriptionDto implements Serializable {
  @SafeString private String endpoint;
  @SafeString private String p256dh;
  @SafeString private String auth;
  @SafeString private String sessionToken;
}
