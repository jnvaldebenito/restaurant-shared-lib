package com.restaurant.shared.security.dto;

import java.io.Serializable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The type Public operation dto.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PublicOperationDto implements Serializable {
  private static final long serialVersionUID = 1L;

  private String httpMethod;
  private String fullPath;
}
