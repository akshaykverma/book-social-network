package com.alibou.book.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service responsible for JWT operations including token generation, validation, and claim extraction.
 * This service works with JwtFilter to provide JWT-based authentication.
 */
/*Types of Claims in JWT
Registered Claims: Predefined claims with reserved names that provide a set of useful, interoperable claims. Examples include:
    sub (subject): The principal being authenticated (typically the user ID or email)
    exp (expiration time): When the token expires
    iat (issued at): When the token was issued
    iss (issuer): Who issued the token
Public Claims: Claims defined by those using JWTs but should be registered in the IANA JSON Web Token Registry to avoid collisions.
Private Claims: Custom claims created to share information between parties that agree on using them.*/

@Service
public class JwtService {
    /* Secret key used for signing JWT tokens, loaded from application properties */
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    
    /* Token expiration time in milliseconds, loaded from application properties  */
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    /*
     * Extracts the username (subject) from a JWT token
     * @param token JWT token string
     * @return the username stored in the token
    */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /*
     * Generic method to extract any claim from a token using a claims resolver function
     * @param token JWT token string
     * @param claimsResolver function to extract specific claim from Claims object
     * @return the extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /*
     * Generates a JWT token for a user without additional claims
     * @param userDetails user details from Spring Security
     * @return JWT token string
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /*
     * Generates a JWT token with additional custom claims
     * @param extraClaims additional claims to include in the token
     * @param userDetails user details from Spring Security
     * @return JWT token string
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /*
     * Builds a JWT token with specified claims, user details, and expiration
     * @param extraClaims additional claims to include in the token
     * @param userDetails user details from Spring Security
     * @param expiration token expiration time in milliseconds
     * @return JWT token string
    */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        var authorities = userDetails.getAuthorities()
                .stream().
                map(GrantedAuthority::getAuthority)
                .toList();
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .claim("authorities", authorities)
                .signWith(getSignInKey())
                .compact();
    }

    /*
     * Validates if a token belongs to the given user and is not expired
     * @param token JWT token string
     * @param userDetails user details from Spring Security
     * @return true if token is valid, false otherwise
    */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /*
     * Checks if a token has expired
     * @param token JWT token string
     * @return true if token is expired, false otherwise
    */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /*
     * Extracts the expiration date from a token
     * @param token JWT token string
     * @return expiration date
    */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Parses the token and extracts all claims
     * @param token JWT token string
     * @return Claims object containing all token claims
    */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /*
     * Decodes the Base64 secret key for signing tokens
     * @return Key object used for signing JWT tokens
    */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
