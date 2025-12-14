package com.ishan.security.jwt_auth_service.controller;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ishan.security.jwt_auth_service.dto.response.ApiResponseDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponseDTO<RegisterResponseDTO>> registerUser(
            @Valid @RequestBody UserRegisterDTO userRegisterDTO,
            HttpServletRequest request) {

        RegisterResponseDTO createdUser = authService.registerUser(userRegisterDTO);
        ApiResponseDTO<RegisterResponseDTO> apiResponse = ApiResponseDTO.<RegisterResponseDTO>builder()
                .status("success")
                .message("User registered successfully! Please verify your email to activate your account.")
                .data(createdUser)
                .timestamp(Instant.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);
    }
}
