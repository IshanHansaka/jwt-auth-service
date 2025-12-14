package com.ishan.security.jwt_auth_service.model;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.ishan.security.jwt_auth_service.enums.UserRole;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "users") // user is a reserved keyword in SQL, so we use users
@Getter
@Setter
@ToString(exclude = "password")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        @Column(name = "user_id")
        private Long userId;

        @Column(unique = true, nullable = false, length = 150, updatable = false)
        private String email;

        @Column(nullable = false, length = 100)
        private String name;

        @JsonIgnore
        @Column(nullable = false)
        private String password;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false, length = 30)
        @Builder.Default
        private UserRole role = UserRole.ROLE_USER; // default role

        @Column(name = "email_verified", nullable = false)
        @Builder.Default
        private boolean verified = false;

        @Column(name = "created_at", updatable = false)
        @CreatedDate
        private LocalDateTime createdAt;

        @Column(name = "last_login")
        private LocalDateTime lastLogin;

        @Column(name = "last_verification_email_sent")
        private LocalDateTime lastVerificationEmailSent;

}
