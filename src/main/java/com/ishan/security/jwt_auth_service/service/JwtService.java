package com.ishan.security.jwt_auth_service.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private long accessTokenDurationMs;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenDurationMs;

    @Value("${jwt.email_verification.expiration}")
    private long emailVerificationTokenDurationMs;

    /**
     * Generate an access token (short-lived)
     */
    public String generateAccessToken(UserDetails userDetails, Map<String, Object> extraClaims) {

        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("role", extractRole(userDetails));
        claims.put("token_type", "access");

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + accessTokenDurationMs))
                .id(UUID.randomUUID().toString())
                .issuer("jwt-auth-service")
                .audience().add("web-client").and()
                .signWith(getSignKey())
                .header().add("typ", "JWT")
                .and()
                .compact();
    }

    /**
     * Generate a refresh token (long-lived)
     */
    public String generateRefreshToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", extractRole(userDetails));
        claims.put("token_type", "refresh");

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshTokenDurationMs))
                .id(UUID.randomUUID().toString())
                .issuer("jwt-auth-service")
                .audience().add("web-client").and()
                .signWith(getSignKey())
                .header().add("typ", "JWT")
                .and()
                .compact();
    }

    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String extractRole(UserDetails userDetails) {

        String role = userDetails.getAuthorities().iterator().next().getAuthority();

        // Remove "ROLE_" prefix if present for JWT token
        String roleWithoutPrefix = role.startsWith("ROLE_") ? role.substring(5) : role;

        return roleWithoutPrefix;
    }
}
