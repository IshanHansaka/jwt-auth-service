package com.ishan.security.jwt_auth_service.service;

import java.util.Objects;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.exception.EmailAlreadyExistsException;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.repository.UserRepository;
import com.ishan.security.jwt_auth_service.util.UserMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    public RegisterResponseDTO registerUser(UserRegisterDTO userRegisterDTO) {

        String encodedPassword = passwordEncoder.encode(userRegisterDTO.getPassword());

        User user = Objects.requireNonNull(userMapper.toEntity(userRegisterDTO, encodedPassword));

        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new EmailAlreadyExistsException(user.getEmail());
        }

        return new RegisterResponseDTO(user.getEmail(), user.getName());
    }

}
