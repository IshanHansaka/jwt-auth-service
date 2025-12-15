package com.ishan.security.jwt_auth_service.service;

import java.time.LocalDateTime;
import java.util.Objects;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.dto.response.JwtTokensDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserLoginDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.exception.EmailAlreadyExistsException;
import com.ishan.security.jwt_auth_service.exception.EmailNotVerifiedException;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.model.UserPrincipal;
import com.ishan.security.jwt_auth_service.repository.UserRepository;
import com.ishan.security.jwt_auth_service.util.UserMapper;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;

    @Transactional
    public RegisterResponseDTO registerUser(UserRegisterDTO userRegisterDTO) {

        String normalizedEmail = normalizeEmail(userRegisterDTO.getEmail());

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyExistsException(userRegisterDTO.getEmail());
        }

        String encodedPassword = passwordEncoder.encode(userRegisterDTO.getPassword());
        User user = Objects.requireNonNull(userMapper.toEntity(userRegisterDTO, encodedPassword, normalizedEmail));

        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new EmailAlreadyExistsException(user.getEmail());
        }

        return new RegisterResponseDTO(user.getEmail(), user.getName());
    }

    @Transactional
    public JwtTokensDTO verifyUser(UserLoginDTO userLoginDTO) {

        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        normalizeEmail(userLoginDTO.getEmail()),
                        userLoginDTO.getPassword()));

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        User user = userPrincipal.getUser();

        if (!user.isVerified()) {
            throw new EmailNotVerifiedException();
        }

        userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now());

        String accessToken = jwtService.generateAccessToken(userPrincipal);
        String refreshToken = jwtService.generateRefreshToken(userPrincipal);

        return new JwtTokensDTO(accessToken, refreshToken);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
