package com.restaurant.shared.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class SharedJwtService {

    @Value("${security.jwt.expiration-in-minutes}")
    private Long expirationInMinutes;

    @Value("${security.jwt.customer-expiration-in-minutes}") // Default 7 days
    private Long customerExpirationInMinutes;

    @Value("${security.jwt.refresh-expiration-in-minutes}")
    private Long refreshExpirationInMinutes;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    public String generateToken(UserDetails user, Map<String, Object> extraClaim) {
        return generateToken(user, extraClaim, expirationInMinutes);
    }

    public String generateToken(UserDetails user, Map<String, Object> extraClaim, Long customExpirationInMinutes) {
        long duration = (customExpirationInMinutes != null) ? customExpirationInMinutes : expirationInMinutes;
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date((duration * 60 * 1000) + issuedAt.getTime());

        return Jwts.builder()
                .header().type("JWT").and()
                .subject(user.getUsername())
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(generateKey(), Jwts.SIG.HS256)
                .claims(extraClaim)
                .compact();
    }

    public String generateRefreshToken(UserDetails user) {
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiration = new Date((refreshExpirationInMinutes * 60 * 1000) + issuedAt.getTime());

        return Jwts.builder()
                .header().type("JWT").and()
                .subject(user.getUsername())
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(generateKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String extractUsername(String jwt) {
        return extractAllClaims(jwt).getSubject();
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String jwt) {
        return Jwts
                .parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public Long getCustomerExpirationInMinutes() {
        return customerExpirationInMinutes;
    }

    private SecretKey generateKey() {
        byte[] passwordDecoded = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(passwordDecoded);
    }
}
