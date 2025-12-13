package com.ishan.security.jwt_auth_service.dto.response;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApiResponseDTO<T> {
    
    private String status;
    private String message;

    @Builder.Default
    private Instant timestamp = Instant.now();

    private String path;
    private T data;
}
