package com.restaurant.shared.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/**
 * The type Shared jwt service.
 */
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

    /**
     * Generate token string.
     *
     * @param user       the user
     * @param extraClaim the extra claim
     * @return the string
     */
    public String generateToken(UserDetails user, Map<String, Object> extraClaim) {
    return generateToken(user, extraClaim, expirationInMinutes);
  }

    /**
     * Generate token string.
     *
     * @param user                      the user
     * @param extraClaim                the extra claim
     * @param customExpirationInMinutes the custom expiration in minutes
     * @return the string
     */
    public String generateToken(
      UserDetails user, Map<String, Object> extraClaim, Long customExpirationInMinutes) {
    long duration =
        (customExpirationInMinutes != null) ? customExpirationInMinutes : expirationInMinutes;
    Date issuedAt = new Date(System.currentTimeMillis());
    Date expiration = new Date((duration * 60 * 1000) + issuedAt.getTime());

    return Jwts.builder()
        .header()
        .type("JWT")
        .and()
        .subject(user.getUsername())
        .issuedAt(issuedAt)
        .expiration(expiration)
        .signWith(generateKey(), Jwts.SIG.HS256)
        .claims(extraClaim)
        .compact();
  }

    /**
     * Generate refresh token string.
     *
     * @param user the user
     * @return the string
     */
    public String generateRefreshToken(UserDetails user) {
    Date issuedAt = new Date(System.currentTimeMillis());
    Date expiration = new Date((refreshExpirationInMinutes * 60 * 1000) + issuedAt.getTime());

    return Jwts.builder()
        .header()
        .type("JWT")
        .and()
        .subject(user.getUsername())
        .issuedAt(issuedAt)
        .expiration(expiration)
        .signWith(generateKey(), Jwts.SIG.HS256)
        .compact();
  }

    /**
     * Extract username string.
     *
     * @param jwt the jwt
     * @return the string
     */
    public String extractUsername(String jwt) {
    return extractAllClaims(jwt).getSubject();
  }

    /**
     * Extract expiration date.
     *
     * @param token the token
     * @return the date
     */
    public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

    /**
     * Is token expired boolean.
     *
     * @param token the token
     * @return the boolean
     */
    public boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

    /**
     * Extract claim t.
     *
     * @param <T>            the type parameter
     * @param token          the token
     * @param claimsResolver the claims resolver
     * @return the t
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

    /**
     * Extract all claims claims.
     *
     * @param jwt the jwt
     * @return the claims
     */
    public Claims extractAllClaims(String jwt) {
    return Jwts.parser().verifyWith(generateKey()).build().parseSignedClaims(jwt).getPayload();
  }

    /**
     * Gets customer expiration in minutes.
     *
     * @return the customer expiration in minutes
     */
    public Long getCustomerExpirationInMinutes() {
    return customerExpirationInMinutes;
  }

  private SecretKey generateKey() {
    byte[] passwordDecoded = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(passwordDecoded);
  }
}
