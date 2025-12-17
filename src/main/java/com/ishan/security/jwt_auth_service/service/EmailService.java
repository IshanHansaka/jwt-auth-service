package com.ishan.security.jwt_auth_service.service;

import java.time.Year;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.ishan.security.jwt_auth_service.exception.EmailSendingException;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.security.token.expiry-minutes}")
    private int expiryMinutes;

    @Value("${spring.application.name}")
    private String appName;

    public void sendVerificationEmail(
            @NonNull String to,
            @NonNull String name,
            @NonNull String verificationUrl) {

        try {
            String subject = "Verify Your Email";

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            // Prepare Thymeleaf context
            Context context = new Context();
            context.setVariable("name", name);
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("expiryMinutes", expiryMinutes);
            context.setVariable("appName", appName);
            context.setVariable("year", Year.now().getValue());

            // Generate HTML content from template
            String htmlContent = Objects.requireNonNull(
                    templateEngine.process("verification-email.html", context),
                    "Email template processing returned null");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);

        } catch (MessagingException e) {
            throw new EmailSendingException("Failed to send verification email: " + e.getMessage(), e);
        }
    }

    public void sendPasswordResetEmail(
            @NonNull String to,
            @NonNull String name,
            @NonNull String resetUrl) {
        try {
            String subject = "Reset Your Password";

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            // Prepare Thymeleaf context
            Context context = new Context();
            context.setVariable("name", name);
            context.setVariable("resetUrl", resetUrl);
            context.setVariable("expiryMinutes", expiryMinutes);
            context.setVariable("appName", appName);
            context.setVariable("year", Year.now().getValue());

            // Generate HTML content from template
            String htmlContent = Objects.requireNonNull(
                    templateEngine.process("password-reset-email.html", context),
                    "Email template processing returned null");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);

        } catch (MessagingException e) {
            throw new EmailSendingException("Failed to send password reset email: " + e.getMessage(), e);
        }
    }
}
