package com.spring.security.jwt.filters;

import com.spring.security.jwt.dto.LoginRequest;
import com.spring.security.jwt.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!request.getServletPath().equals("/generate-token")) {
            filterChain.doFilter(request, response);
            return;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
        Authentication authResult = authenticationManager.authenticate(authToken);

        if (authResult.isAuthenticated()) {
            String token = jwtUtil.generateToken(authResult.getName(), 15); //15min
            response.setHeader("Authorization", "Bearer " + token); //response will be in header under Authorization Key
        }
    }
}
/*
User (React)
     │
             │ 1. Login (username/password)
     ▼
Auth Server (Spring Boot / Keycloak)
     │
             │ ✔ Validate username/password (DB check)
     │ ✔ Generate JWT
     ▼
User gets JWT
     │
             │ 2. API Request with JWT
     ▼
Backend (Spring Boot - Spring Security)
     │
             │ ✔ Validate JWT (signature + expiry) (Backend validates token locally using secret/public key) and Auth Server and Backend are configured with the same key (or related keys) Auth Server → signs JWT using SECRET_KEY Backend → verifies JWT using SAME SECRET_KEY
     │ ✔ Extract user
     ▼
Protected API Response


*/
