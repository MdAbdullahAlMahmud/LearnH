package com.mkrlabs.hadis_sikhi.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.exp}")
    private long tokenValidity;

    private static final String SECRET_KEY = "d8282d5dd7924e0734c37fafdf546a18a3f6578f8ef8e1717d5444406ac95db9";
    public String extractUsername(String token){
        return  extractClaim(token,Claims::getSubject);
    }

    public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails){
        return  Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        return  generateToken(new HashMap<>(),userDetails);
    }

    public boolean isValidToken(String token , UserDetails userDetails){

        final  String userName = extractUsername(token);
        return  (userName.equals(userDetails.getUsername())) && isTokenExpired(token);

    }

    public boolean isTokenExpired(String token){
        return  extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return  extractClaim(token, Claims::getExpiration);
    }


    public <T> T extractClaim(String token , Function<Claims, T> claimsResolver){
        final  Claims claims = extractAllClaims(token);
        return  claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
