package com.ishan.security.jwt_auth_service.controller;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ishan.security.jwt_auth_service.dto.response.ApiResponseDTO;
import com.ishan.security.jwt_auth_service.dto.response.JwtTokensDTO;
import com.ishan.security.jwt_auth_service.dto.response.LoginResponseDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserLoginDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.service.AuthService;
import com.ishan.security.jwt_auth_service.service.JwtService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

        private final AuthService authService;
        private final JwtService jwtService;

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

        @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
        public ResponseEntity<ApiResponseDTO<LoginResponseDTO>> verifyUser(
                        @Valid @RequestBody UserLoginDTO userLoginDTO,
                        HttpServletRequest request) {

                JwtTokensDTO tokens = authService.verifyUser(userLoginDTO);

                // HttpOnly refresh token cookie
                ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", tokens.getRefreshToken())
                                .httpOnly(true)
                                .secure(true) // prod only
                                .path("/api/v1/auth/refresh")
                                .maxAge(Objects.requireNonNull(
                                                Duration.ofMillis(jwtService.getRefreshTokenDurationMs())))
                                .sameSite("Strict") // unless cross-site auth needed
                                .build();

                LoginResponseDTO loginResponse = new LoginResponseDTO();
                loginResponse.setAccessToken(tokens.getAccessToken());

                ApiResponseDTO<LoginResponseDTO> apiResponse = ApiResponseDTO.<LoginResponseDTO>builder()
                                .status("success")
                                .message("Login successful")
                                .data(loginResponse)
                                .timestamp(Instant.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                                .body(apiResponse);
        }
}
