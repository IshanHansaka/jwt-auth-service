package com.ishan.security.jwt_auth_service.job;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;
import com.ishan.security.jwt_auth_service.repository.PasswordResetTokenRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupJob {

    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    /**
     * Cleanup expired email verification tokens
     *
     * Runs every 1 hour
     */
    @Transactional
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredEmailVerificationTokens() {
        int deletedCount = emailVerificationTokenRepository.deleteExpired();
        log.info("Expired email verification tokens cleaned up: {}", deletedCount);
    }

    /**
     * Cleanup expired password reset tokens
     *
     * Runs every 1 hour
     */
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupPasswordResetTokens() {
        int count = passwordResetTokenRepository.deleteExpired();
        log.info("Password reset tokens cleaned up: {}", count);
    }
}
