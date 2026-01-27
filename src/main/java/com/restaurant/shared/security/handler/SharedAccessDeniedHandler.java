package com.restaurant.shared.security.handler;

import com.restaurant.shared.security.handler.utils.HandlerResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SharedAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String message = "Acceso denegado: no posees los permisos necesarios para acceder a esta función. Contacta al administrador si crees que esto es un error.";
        HandlerResponse.generateHandleResponse(request, response, accessDeniedException, HttpStatus.FORBIDDEN, message);
    }
}
