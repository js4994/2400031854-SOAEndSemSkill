
package com.example.jwtgeneration.controller;

import java.util.Map;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import com.example.jwtgeneration.service.JwtService;

@RestController
@RequestMapping("/api/auth")
public class JwtController {

    private final JwtService jwtService;

    // Constructor
    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // 1. Generate JWT Token
    @PostMapping("/generate")
    public Map<String, String> generateToken(
            @RequestBody Map<String, Object> payload) {

        String token = jwtService.generateToken(payload);

        return Map.of("token", token);
    }

    // 2. Validate JWT Token
    @PostMapping("/validate")
    public Map<String, Boolean> validateToken(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");

        boolean valid = token != null &&
                        jwtService.validateToken(token);

        return Map.of("valid", valid);
    }

    // 3. Protected Endpoint
    @GetMapping("/protected")
    @SecurityRequirement(name = "Bearer Authentication")
    public Map<String, String> protectedEndpoint(
            @RequestHeader(
                value = "Authorization",
                required = false
            ) String authorization) {

        if (authorization == null ||
            !authorization.startsWith("Bearer ")) {

            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "JWT token missing"
            );
        }

        String token = authorization.substring(7);

        if (!jwtService.validateToken(token)) {

            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Invalid or expired token"
            );
        }

        return Map.of(
            "message",
            "JWT authentication successful"
        );
    }
}
