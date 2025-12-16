package com.ishan.security.jwt_auth_service.service;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.model.EmailVerificationToken;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;
import com.ishan.security.jwt_auth_service.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailService emailService;
    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Value("${app.backend-url}")
    private String backendUrl;

    @Transactional
    public void sendVerificationEmail(User user) {

        String token = UUID.randomUUID().toString();

        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .used(false)
                .createdAt(LocalDateTime.now())
                .build();

        tokenRepository.save(verificationToken);
        String verificationUrl = backendUrl + "/api/v1/auth/verify-email?token=" + token;

        try {
            emailService.sendVerificationEmail(user.getEmail(), user.getName(), verificationUrl);
            userRepository.updateLastVerificationEmailSent(user.getUserId(), LocalDateTime.now());
        } catch (Exception e) {
            throw new RuntimeException("Failed to send verification email: " + e.getMessage(), e);
        }
    }
}
