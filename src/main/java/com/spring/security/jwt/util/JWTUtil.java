package com.spring.security.jwt.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JWTUtil {

    private static final String SECRET_KEY = "your-secure-secret-key-min-32bytes";
    private static final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));


    // Generate JWT Token
    public String generateToken(String username, long expiryMinutes) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiryMinutes * 60 * 1000)) //in milliseconds
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateAndExtractUsername(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (JwtException e) {
            return null; // Invalid or expired JWT
        }
    }

    public void generateAccessAndRefreshToken(HttpServletResponse response, Authentication authResult) {
        String token = generateToken(authResult.getName(), 15); //15min, authResult.getName() - username (or principal name) of the authenticated user
        response.setHeader("Authorization", "Bearer " + token); //response will be in header under Authorization Key
        String refreshToken = generateToken(authResult.getName(), 7 * 24 * 60); //7day

        // Set Refresh Token in HttpOnly Cookie
        //we can also send it in response body but then client has to store it in local storage or in-memory
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true); //prevent javascript from accessing it
        refreshCookie.setSecure(true); // sent only over HTTPS
        refreshCookie.setPath("/refresh-token"); // Cookie available only for refresh endpoint
        refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days expiry
        response.addCookie(refreshCookie);
    }
}


