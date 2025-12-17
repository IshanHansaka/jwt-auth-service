package com.ishan.security.jwt_auth_service.service;

import java.time.Duration;
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
import com.ishan.security.jwt_auth_service.dto.response.LoginResponseDTO;
import com.ishan.security.jwt_auth_service.dto.response.RegisterResponseDTO;
import com.ishan.security.jwt_auth_service.exception.EmailAlreadyExistsException;
import com.ishan.security.jwt_auth_service.exception.EmailNotVerifiedException;
import com.ishan.security.jwt_auth_service.exception.InvalidRefreshTokenException;
import com.ishan.security.jwt_auth_service.exception.ResendEmailCooldownException;
import com.ishan.security.jwt_auth_service.exception.UserNotFoundException;
import com.ishan.security.jwt_auth_service.model.EmailVerificationToken;
import com.ishan.security.jwt_auth_service.model.PasswordResetToken;
import com.ishan.security.jwt_auth_service.model.User;
import com.ishan.security.jwt_auth_service.model.UserPrincipal;
import com.ishan.security.jwt_auth_service.repository.EmailVerificationTokenRepository;
import com.ishan.security.jwt_auth_service.repository.PasswordResetTokenRepository;
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
    private final CustomUserDetailsService customUserDetailsService;
    private final EmailNormalizer emailNormalizer;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    @Value("${app.security.resend-email-cooldown-minutes}")
    private int cooldownMinutes;

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

    public void resendEmail(String email) {

        String normalizedEmail = emailNormalizer.normalize(email);
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (user.isVerified()) {
            throw new IllegalStateException("User is already verified");
        }

        // Cooldown check
        LocalDateTime lastSent = user.getLastVerificationEmailSent();
        if (lastSent != null &&
                lastSent.isAfter(LocalDateTime.now().minusMinutes(cooldownMinutes))) {
            long waitMinutes = cooldownMinutes - Duration.between(
                    lastSent, LocalDateTime.now()).toMinutes();
            throw new ResendEmailCooldownException("Please wait " + waitMinutes + " minutes before requesting again");
        }

        emailVerificationService.sendVerificationEmail(user);

        // Update last sent timestamp
        user.setLastVerificationEmailSent(java.time.LocalDateTime.now());
        userRepository.save(user);

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
