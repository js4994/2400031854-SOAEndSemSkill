package com.example.jwtgeneration.service;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    // Generate JWT Token
    public String generateToken(Map<String, Object> payload) {

        // Configure secret key
        SecretKey key = Keys.hmacShaKeyFor(
            Decoders.BASE64.decode(secret)
        );

        long currentTime = System.currentTimeMillis();

        // Generate signed JWT
        String token = Jwts.builder()
                .claims(payload)
                .issuedAt(new Date(currentTime))
                .expiration(new Date(currentTime + expiration))
                .signWith(key)
                .compact();

        return token;
    }

    // Validate JWT Token
    public boolean validateToken(String token) {

        try {
            SecretKey key = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(secret)
            );

            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);

            return true;

        } catch (Exception e) {
            return false;
        }
    }
}