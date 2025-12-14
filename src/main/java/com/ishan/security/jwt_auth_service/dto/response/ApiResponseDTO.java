package com.ishan.security.jwt_auth_service.dto.response;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Standardized API Response Template
 * Supports success, error, and validation.
 *
 * @param <T> Type of the response payload
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApiResponseDTO<T> {
    
    private String status;
    private String message;
    private String path;
    private T data;

    /** Timestamp when the response was issued */
    @Builder.Default
    private Instant timestamp = Instant.now();
}
