package com.restaurant.shared.security.handler;

import com.restaurant.shared.security.handler.utils.HandlerResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * The type Shared authentication entry point.
 */
@Component
public class SharedAuthenticationEntryPoint implements AuthenticationEntryPoint {
  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {
    String message =
        "No se encontraron credenciales de autenticación. Por favor inicia sesión para acceder a esta función.";
    HandlerResponse.generateHandleResponse(
        request, response, authException, HttpStatus.UNAUTHORIZED, message);
  }
}
