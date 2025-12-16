package com.ishan.security.jwt_auth_service.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
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

    /**
     * Generate an access token (short-lived)
     */
    public String generateAccessToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", extractRole(userDetails));
        claims.put("token_type", "access");

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + accessTokenDurationMs))
                .id(UUID.randomUUID().toString())
                .issuer("jwt-auth-service")
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

    /**
     * Validate an access token
     */
    public boolean validateAccessToken(String token, UserDetails userDetails) {

        final String username = extractUsername(token);
        final String type = extractClaim(token, claims -> claims.get("token_type", String.class));
        return username.equals(userDetails.getUsername())
                && !isTokenExpired(token)
                && "access".equals(type);
    }

    /**
     * Validate a refresh token
     */
    public boolean validateRefreshToken(String refreshToken, UserDetails userDetails) {
        final String username = extractUsername(refreshToken);
        final String type = extractClaim(refreshToken, claims -> claims.get("token_type", String.class));
        return username.equals(userDetails.getUsername())
                && !isTokenExpired(refreshToken)
                && "refresh".equals(type);
    }

    public String extractUsername(String token) throws JwtException {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public long getAccessTokenDurationMs() {
        return accessTokenDurationMs;
    }

    public long getRefreshTokenDurationMs() {
        return refreshTokenDurationMs;
    }
}
