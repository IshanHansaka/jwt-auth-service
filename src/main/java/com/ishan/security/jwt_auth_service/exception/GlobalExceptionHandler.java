package com.ishan.security.jwt_auth_service.exception;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.ishan.security.jwt_auth_service.dto.response.ApiResponseDTO;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Handle validation errors (@Valid)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        String errorMessages = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", "));

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(errorMessages)
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    // Handle generic exceptions
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleException(
            Exception ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    // Handle email already exists exception
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // Handle email not verify exception
    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // Handle bad credentials
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message("Invalid email or password")
                .path(request.getRequestURI())
                .timestamp(Instant.now())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // Handle Jwt invildations
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleJwtException(
        JwtException ex,
        HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message("Invalid or expired token")
                .path(request.getRequestURI())
                .timestamp(Instant.now())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // Handle email not sending
    @ExceptionHandler(EmailSendingException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleEmailSending(
            EmailSendingException ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    // Handle user not found exception
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponseDTO<Object>> handleUserNotFound(
            UserNotFoundException ex,
            HttpServletRequest request) {

        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                .status("error")
                .message(ex.getMessage())
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .data(null)
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }
}
