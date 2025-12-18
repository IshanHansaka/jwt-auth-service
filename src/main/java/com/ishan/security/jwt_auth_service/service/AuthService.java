package com.ishan.security.jwt_auth_service.service;

import java.time.LocalDateTime;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ishan.security.jwt_auth_service.dto.response.JwtTokensDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.exception.EmailAlreadyExistsException;
import com.ishan.security.jwt_auth_service.exception.EmailNotVerifiedException;
import com.ishan.security.jwt_auth_service.exception.InvalidRefreshTokenException;
import com.ishan.security.jwt_auth_service.model.EmailVerificationToken;
import com.ishan.security.jwt_auth_service.model.PasswordResetToken;
import com.ishan.security.jwt_auth_service.model.RefreshToken;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.model.UserPrincipal;
import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;
import com.ishan.security.jwt_auth_service.repository.PasswordResetTokenRepository;
import com.ishan.security.jwt_auth_service.repository.RefreshTokenRepository;
import com.ishan.security.jwt_auth_service.repository.UserRepository;
import com.ishan.security.jwt_auth_service.util.EmailNormalizer;
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
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final EmailNormalizer emailNormalizer;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.security.resend-email-cooldown-minutes}")
    private int cooldownMinutes;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenDurationMs;

    @Transactional
    public RegisterResponseDTO registerUser(String email, String password, String name) {

        String normalizedEmail = emailNormalizer.normalize(email);

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyExistsException(email);
        }

        String encodedPassword = passwordEncoder.encode(password);
        User user = Objects.requireNonNull(userMapper.toEntity(name, encodedPassword, normalizedEmail));

        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new EmailAlreadyExistsException(user.getEmail());
        }

        emailVerificationService.sendVerificationEmail(user);

        return new RegisterResponseDTO(user.getEmail(), user.getName());
    }

    @Transactional
    public JwtTokensDTO verifyUser(String email, String password) {

        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        emailNormalizer.normalize(email),
                        password));

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        User user = userPrincipal.getUser();

        if (!user.isVerified()) {
            throw new EmailNotVerifiedException();
        }

        userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now());

        String accessToken = jwtService.generateAccessToken(userPrincipal);
        String refreshToken = jwtService.generateRefreshToken(userPrincipal);

        refreshTokenRepository.save(
                RefreshToken.builder()
                        .token(refreshToken)
                        .user(user)
                        .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenDurationMs / 1000))
                        .revoked(false)
                        .createdAt(LocalDateTime.now())
                        .build());

        return new JwtTokensDTO(accessToken, refreshToken);
    }

    @Transactional
    public void verifyEmail(String token) {

        EmailVerificationToken verificationToken = emailVerificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid token"));

        if (verificationToken.isUsed()) {
            throw new BadCredentialsException("Token already used");
        }

        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadCredentialsException("Token expired");
        }

        User user = verificationToken.getUser();
        userRepository.updateVerified(user.getUserId(), true);
        emailVerificationTokenRepository.updateUsed(verificationToken.getTokenId(), true);
    }

    @Transactional
    public JwtTokensDTO getRefreshAccessToken(String refreshToken) {

        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));

        if (storedToken.isRevoked() || storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidRefreshTokenException("Refresh token revoked or expired");
        }

        User user = storedToken.getUser();
        UserDetails userDetails = new UserPrincipal(user);

        // Rotate refresh token
        storedToken.setRevoked(true);

        String newRefreshToken = jwtService.generateRefreshToken(userDetails);
        refreshTokenRepository.save(
                RefreshToken.builder()
                        .token(newRefreshToken)
                        .user(user)
                        .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenDurationMs / 1000))
                        .revoked(false)
                        .createdAt(LocalDateTime.now())
                        .build());

        String newAccessToken = jwtService.generateAccessToken(userDetails);

        JwtTokensDTO tokens = new JwtTokensDTO(newAccessToken, newRefreshToken);

        return tokens;
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(token -> {
                    Long userId = token.getUser().getUserId();
                    refreshTokenRepository.revokeAllByUserId(userId);
                });
    }

    public void resendEmail(String email) {

        String normalizedEmail = emailNormalizer.normalize(email);

        userRepository.findByEmail(normalizedEmail).ifPresent(user -> {
            if (user.isVerified()) {
                // Do not reveal verification status
                return;
            }

            LocalDateTime lastSent = user.getLastVerificationEmailSent();
            if (lastSent != null && lastSent.isAfter(LocalDateTime.now().minusMinutes(cooldownMinutes))) {
                // Respect cooldown silently without throwing
                return;
            }

            emailVerificationService.sendVerificationEmail(user);
            userRepository.updateLastVerificationEmailSent(user.getUserId(), LocalDateTime.now());
        });

        // Intentionally always return silently to avoid email enumeration
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {

        PasswordResetToken resetToken = validateToken(token);
        User user = resetToken.getUser();

        // Update password
        userRepository.updatePassword(
                user.getUserId(),
                passwordEncoder.encode(newPassword));

        // Mark token as used
        passwordResetTokenRepository.updateUsed(resetToken.getTokenId());

        // Invalidate all other reset tokens
        passwordResetTokenRepository.invalidateAllForUser(user.getUserId());
    }

    public PasswordResetToken validateToken(String token) {
        PasswordResetToken resetToken = passwordResetTokenRepository
                .findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid token"));

        if (resetToken.isUsed()) {
            throw new BadCredentialsException("Token already used");
        }

        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadCredentialsException("Token expired");
        }

        return resetToken;
    }
}
