package com.ishan.security.jwt_auth_service.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping("/api/v1/health-check")
@SecurityRequirement(name = "bearerAuth")
public class HealthCheckController {

    @GetMapping
    public ResponseEntity<String> healthCheck() {
        String message = "Server is running successfully";
        return ResponseEntity.status(HttpStatus.OK).body(message);
    }
}
