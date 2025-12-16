package com.ishan.security.jwt_auth_service.controller;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ishan.security.jwt_auth_service.dto.request.ResendEmailRequestDTO;
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

        @GetMapping("/verify-email")
        public ResponseEntity<ApiResponseDTO<Void>> verifyEmail(@RequestParam String token,
                        HttpServletRequest request) {

                authService.verifyEmail(token);

                ApiResponseDTO<Void> apiResponse = ApiResponseDTO.<Void>builder()
                                .status("success")
                                .message("Email verified successfully")
                                .data(null)
                                .timestamp(Instant.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.ok(apiResponse);
        }

        @PostMapping("/refresh")
        public ResponseEntity<ApiResponseDTO<LoginResponseDTO>> refreshToken(
                        @CookieValue(name = "refreshToken", required = false) String refreshToken,
                        HttpServletRequest request) {

                if (refreshToken == null || refreshToken.isEmpty()) {
                        ApiResponseDTO<LoginResponseDTO> response = ApiResponseDTO.<LoginResponseDTO>builder()
                                        .status("error")
                                        .message("No active session found or already logged out")
                                        .data(null)
                                        .timestamp(Instant.now())
                                        .path(request.getRequestURI())
                                        .build();

                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }

                LoginResponseDTO loginResponse = authService.getRefreshAccessToken(refreshToken);

                ApiResponseDTO<LoginResponseDTO> apiResponse = ApiResponseDTO.<LoginResponseDTO>builder()
                                .status("success")
                                .message("Token refreshed successfully")
                                .data(loginResponse)
                                .timestamp(Instant.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.ok(apiResponse);
        }

        @PostMapping("/logout")
        public ResponseEntity<ApiResponseDTO<Object>> logout(
                        @CookieValue(name = "refreshToken", required = false) String refreshToken,
                        HttpServletRequest request) {

                if (refreshToken == null || refreshToken.isEmpty()) {
                        ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                                        .status("error")
                                        .message("No active session found or already logged out")
                                        .data(null)
                                        .timestamp(Instant.now())
                                        .path(request.getRequestURI())
                                        .build();

                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }

                // Clear the refresh token cookie
                ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                                .httpOnly(true)
                                .secure(true)
                                .path("/api/v1/auth/refresh")
                                .maxAge(0)
                                .sameSite("Strict")
                                .build();

                ApiResponseDTO<Object> apiResponse = ApiResponseDTO.builder()
                                .status("success")
                                .message("Logged out successfully")
                                .data(null)
                                .timestamp(Instant.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
                                .body(apiResponse);
        }

        @PostMapping("/resend-email")
        public ResponseEntity<ApiResponseDTO<Object>> resendEmail(
                        @Valid @RequestBody ResendEmailRequestDTO resendEmailRequestDTO,
                        HttpServletRequest httpRequest) {

                authService.resendEmail(resendEmailRequestDTO);

                ApiResponseDTO<Object> response = ApiResponseDTO.builder()
                                .status("success")
                                .message("Verification email resent successfully")
                                .timestamp(Instant.now())
                                .path(httpRequest.getRequestURI())
                                .data(null)
                                .build();

                return ResponseEntity.ok(response);
        }
}
