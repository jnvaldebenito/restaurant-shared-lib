package com.restaurant.shared.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ResponseErrorDto {
    private String code;
    private String message;
    @JsonIgnore
    private String url;
    @JsonIgnore
    private String method;
    @JsonIgnore
    @JsonFormat(pattern = "dd-MM-yyyy HH:mm:ss")
    private LocalDateTime timestamp;
    @JsonIgnore
    private String backendMessage;
}
