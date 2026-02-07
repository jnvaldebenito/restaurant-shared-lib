package com.restaurant.shared.dto;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;

/**
 * The type Error response.
 */
@Data
@Builder
public class ErrorResponse {
  private LocalDateTime timestamp;
  private int status;
  private String error;
  private String message;
  private String path;
}
