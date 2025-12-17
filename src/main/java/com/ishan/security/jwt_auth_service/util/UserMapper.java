package com.ishan.security.jwt_auth_service.util;

import java.time.LocalDateTime;

import org.springframework.stereotype.Component;

import com.ishan.security.jwt_auth_service.model.User;

import lombok.NonNull;

@Component
public class UserMapper {

    @NonNull
    public User toEntity(@NonNull String name, @NonNull String encodedPassword,
            @NonNull String normalizedEmail) {
        return User.builder()
                .email(normalizedEmail)
                .name(name)
                .password(encodedPassword)
                .createdAt(LocalDateTime.now())
                .build();
    }

}
