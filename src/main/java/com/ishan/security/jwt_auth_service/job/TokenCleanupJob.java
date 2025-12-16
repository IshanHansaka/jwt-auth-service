package com.ishan.security.jwt_auth_service.job;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupJob {

    private final EmailVerificationTokenRepository tokenRepository;

    /**
     * Cleanup expired email verification tokens
     *
     * Runs every 1 hour
     */
    @Transactional
    @Scheduled(cron = "0 0 * * * *")
    public void cleanupExpiredEmailVerificationTokens() {
        int deletedCount = tokenRepository.deleteExpired();
        log.info("Expired email verification tokens cleaned up: {}", deletedCount);
    }
}
