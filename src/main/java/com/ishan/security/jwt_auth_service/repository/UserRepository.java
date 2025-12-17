package com.ishan.security.jwt_auth_service.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.ishan.security.jwt_auth_service.model.User;

import jakarta.transaction.Transactional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

        Optional<User> findByEmail(String email);

        boolean existsByEmail(String email);

        @Transactional
        @Modifying
        @Query("""
                            UPDATE User u
                            SET u.lastLogin = :lastLogin
                            WHERE u.userId = :userId
                        """)
        void updateLastLogin(@Param("userId") Long userId,
                        @Param("lastLogin") LocalDateTime lastLogin);

        @Transactional
        @Modifying
        @Query("""
                            UPDATE User u
                            SET u.verified = :verified
                            WHERE u.userId = :userId
                        """)
        void updateVerified(@Param("userId") Long userId,
                        @Param("verified") boolean verified);

        @Transactional
        @Modifying
        @Query("""
                            UPDATE User u
                            SET u.lastVerificationEmailSent = :lastVerificationEmailSent
                            WHERE u.userId = :userId
                        """)
        void updateLastVerificationEmailSent(@Param("userId") Long userId,
                        @Param("lastVerificationEmailSent") LocalDateTime lastVerificationEmailSent);

        @Transactional
        @Modifying
        @Query("""
                            UPDATE User u
                            SET u.lastPasswordResetEmailSent = :lastPasswordResetEmailSent
                            WHERE u.userId = :userId
                        """)
        void updateLastPasswordResetEmailSent(@Param("userId") Long userId,
                        @Param("lastPasswordResetEmailSent") LocalDateTime lastPasswordResetEmailSent);

        @Modifying
        @Query("""
                        UPDATE User u
                        SET u.password = :password
                        WHERE u.userId = :userId
                        """)
        void updatePassword(Long userId, String password);
}
