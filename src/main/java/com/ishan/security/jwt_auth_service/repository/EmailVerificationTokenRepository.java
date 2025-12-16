package com.ishan.security.jwt_auth_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.ishan.security.jwt_auth_service.model.EmailVerificationToken;

import jakarta.transaction.Transactional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> findByToken(String token);

    @Transactional
    @Modifying
    @Query("""
                UPDATE EmailVerificationToken e
                SET e.used = :used
                WHERE e.tokenId = :tokenId
            """)
    void updateUsed(@Param("tokenId") Long tokenId,
            @Param("used") boolean used);

    @Transactional
    @Modifying
    @Query("""
                DELETE FROM EmailVerificationToken e
                WHERE e.expiresAt < CURRENT_TIMESTAMP
            """)
    int deleteExpired();
}
