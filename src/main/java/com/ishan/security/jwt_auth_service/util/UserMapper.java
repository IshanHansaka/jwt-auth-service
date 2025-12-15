package com.ishan.security.jwt_auth_service.util;

import java.time.LocalDateTime;

import org.springframework.stereotype.Component;

import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.model.User;

import lombok.NonNull;

@Component
public class UserMapper {

    @NonNull
    public User toEntity(@NonNull UserRegisterDTO dto, @NonNull String encodedPassword,
            @NonNull String normalizedEmail) {
        return User.builder()
                .email(normalizedEmail)
                .name(dto.getName())
                .password(encodedPassword)
                .createdAt(LocalDateTime.now())
                .build();
    }

}
