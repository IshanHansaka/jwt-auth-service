package com.ishan.security.jwt_auth_service.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.exception.ResendEmailCooldownException;
import com.ishan.security.jwt_auth_service.model.PasswordResetToken;
import com.ishan.security.jwt_auth_service.repository.PasswordResetTokenRepository;
import com.ishan.security.jwt_auth_service.repository.UserRepository;
import com.ishan.security.jwt_auth_service.util.EmailNormalizer;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

        private final EmailService emailService;
        private final PasswordResetTokenRepository passwordResetTokenRepository;
        private final UserRepository userRepository;
        private final EmailNormalizer emailNormalizer;

        @Value("${app.frontend-url}")
        private String frontendUrl;

        @Value("${app.security.token.expiry-minutes}")
        private int expiryMinutes;

        @Value("${app.security.resend-email-cooldown-minutes}")
        private int cooldownMinutes;

        @Transactional
        public void requestPasswordReset(String email) {

                userRepository.findByEmail(emailNormalizer.normalize(email))
                                .ifPresent(user -> {

                                        // Cooldown check
                                        LocalDateTime lastSent = user.getLastPasswordResetEmailSent();
                                        if (lastSent != null &&
                                                        lastSent.isAfter(LocalDateTime.now()
                                                                        .minusMinutes(cooldownMinutes))) {
                                                long waitMinutes = cooldownMinutes - Duration.between(
                                                                lastSent,
                                                                LocalDateTime.now()).toMinutes();
                                                throw new ResendEmailCooldownException("Please wait " + waitMinutes
                                                                + " minutes before requesting again");
                                        }

                                        // Invalidate previous tokens (recommended)
                                        passwordResetTokenRepository.invalidateAllForUser(user.getUserId());

                                        String token = UUID.randomUUID().toString();

                                        PasswordResetToken resetToken = PasswordResetToken.builder()
                                                        .token(token)
                                                        .user(user)
                                                        .expiresAt(LocalDateTime.now().plusMinutes(expiryMinutes))
                                                        .used(false)
                                                        .createdAt(LocalDateTime.now())
                                                        .build();

                                        passwordResetTokenRepository.save(resetToken);

                                        String resetUrl = frontendUrl + "/reset-password?token=" + token;

                                        emailService.sendPasswordResetEmail(
                                                        user.getEmail(),
                                                        user.getName(),
                                                        resetUrl);

                                        userRepository.updateLastPasswordResetEmailSent(
                                                        user.getUserId(),
                                                        LocalDateTime.now());
                                });
        };
}
