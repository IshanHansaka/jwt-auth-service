package com.ishan.security.jwt_auth_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.ishan.security.jwt_auth_service.model.PasswordResetToken;

import jakarta.transaction.Transactional;

@Repository
public interface PasswordResetTokenRepository
        extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    @Modifying
    @Transactional
    @Query("""
                UPDATE PasswordResetToken t
                SET t.used = true
                WHERE t.tokenId = :tokenId
            """)
    void updateUsed(@Param("tokenId") Long tokenId);

    @Modifying
    @Transactional
    @Query("""
                UPDATE PasswordResetToken t
                SET t.used = true
                WHERE t.user.userId = :userId
            """)
    void invalidateAllForUser(@Param("userId") Long userId);

    @Transactional
    @Modifying
    @Query("""
                DELETE FROM PasswordResetToken p
                WHERE p.expiresAt < CURRENT_TIMESTAMP
            """)
    int deleteExpired();
}
