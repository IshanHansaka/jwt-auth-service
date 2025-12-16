package com.ishan.security.jwt_auth_service.service;

import java.time.LocalDateTime;
import java.util.Objects;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.dto.request.ResendEmailRequestDTO;
import com.ishan.security.jwt_auth_service.dto.response.JwtTokensDTO;
import com.ishan.security.jwt_auth_service.dto.response.LoginResponseDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserLoginDTO;
import com.ishan.security.jwt_auth_service.dto.user.UserRegisterDTO;
import com.ishan.security.jwt_auth_service.exception.EmailAlreadyExistsException;
import com.ishan.security.jwt_auth_service.exception.EmailNotVerifiedException;
import com.ishan.security.jwt_auth_service.exception.InvalidRefreshTokenException;
import com.ishan.security.jwt_auth_service.exception.ResendEmailCooldownException;
import com.ishan.security.jwt_auth_service.exception.UserNotFoundException;
import com.ishan.security.jwt_auth_service.model.EmailVerificationToken;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.model.UserPrincipal;
import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;
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
    private final EmailVerificationService emailVerificationService;
    private final EmailVerificationTokenRepository tokenRepository;
    private final CustomUserDetailsService customUserDetailsService;

    private static final int COOLDOWN_MINUTES = 5;

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

        emailVerificationService.sendVerificationEmail(user);

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

    @Transactional
    public void verifyEmail(String token) {

        EmailVerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid token"));

        if (verificationToken.isUsed()) {
            throw new BadCredentialsException("Token already used");
        }

        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadCredentialsException("Token expired");
        }

        User user = verificationToken.getUser();
        userRepository.updateVerified(user.getUserId(), true);
        tokenRepository.updateUsed(verificationToken.getTokenId(), true);
    }

    public LoginResponseDTO getRefreshAccessToken(String refreshToken) {

        String username = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        if (!jwtService.validateRefreshToken(refreshToken, userDetails)) {
            throw new InvalidRefreshTokenException("Invalid or expired refresh token");
        }

        String newAccessToken = jwtService.generateAccessToken(userDetails);

        LoginResponseDTO loginResponse = new LoginResponseDTO();
        loginResponse.setAccessToken(newAccessToken);

        return loginResponse;
    }

    public void resendEmail(ResendEmailRequestDTO resendEmailRequestDTO) {

        String email = normalizeEmail(resendEmailRequestDTO.getEmail());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (user.isVerified()) {
            throw new IllegalStateException("User is already verified");
        }

        // Cooldown check
        if (user.getLastVerificationEmailSent() != null &&
                user.getLastVerificationEmailSent()
                        .isAfter(java.time.LocalDateTime.now().minusMinutes(COOLDOWN_MINUTES))) {
            long waitMinutes = COOLDOWN_MINUTES - java.time.Duration.between(
                    user.getLastVerificationEmailSent(), java.time.LocalDateTime.now()).toMinutes();
            throw new ResendEmailCooldownException("Please wait " + waitMinutes + " minutes before requesting again");
        }

        emailVerificationService.sendVerificationEmail(user);

        // Update last sent timestamp
        user.setLastVerificationEmailSent(java.time.LocalDateTime.now());
        userRepository.save(user);

    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
