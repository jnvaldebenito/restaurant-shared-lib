package com.restaurant.shared.security.handler.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.restaurant.shared.dto.ResponseErrorDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * The type Handler response.
 */
public final class HandlerResponse {

    /**
     * Generate handle response.
     *
     * @param request   the request
     * @param response  the response
     * @param exception the exception
     * @param status    the status
     * @param message   the message
     * @throws IOException the io exception
     */
    public static void generateHandleResponse(
      HttpServletRequest request,
      HttpServletResponse response,
      Exception exception,
      HttpStatus status,
      String message)
      throws IOException {
    ResponseErrorDto responseErrorDto = new ResponseErrorDto();
    responseErrorDto.setBackendMessage(exception.getLocalizedMessage());
    responseErrorDto.setUrl(request.getRequestURL().toString());
    responseErrorDto.setMethod(request.getMethod());
    responseErrorDto.setTimestamp(LocalDateTime.now());
    responseErrorDto.setMessage(message);
    responseErrorDto.setCode(String.valueOf(status.value()));

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(status.value());

    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.registerModule(new JavaTimeModule());
    String apiErrorAsString = objectMapper.writeValueAsString(responseErrorDto);
    response.getWriter().write(apiErrorAsString);
  }

  private HandlerResponse() {}
}
