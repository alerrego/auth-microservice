package com.proyecto.auth.jwt;



import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;



@Service

public class JwtService {



    // Inyectamos las claves desde application.properties o variables de entorno

    @Value("${jwt.private.key}")

    private String privateKeyString;



    @Value("${jwt.public.key}")

    private String publicKeyString;



    @Value("${jwt.expiration.ms}")

    private long jwtExpirationMs; // Ej: 86400000 para 24 horas



    public String getToken(UserDetails user) {

        return getToken(new HashMap<>(), user);

    }



    public String getToken(Map<String, Object> extraClaims, UserDetails user) {

        return Jwts.builder()

                .setClaims(extraClaims)

                .setSubject(user.getUsername())

                .setIssuedAt(new Date(System.currentTimeMillis()))

                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))

                .signWith(getPrivateKey(), SignatureAlgorithm.RS256) // CAMBIO IMPORTANTE: RS256

                .compact();

    }



    // Nota: En un microservicio que NO es Auth (ej. Ventas), solo necesitarías este método

    // y usarías la PUBLIC Key.

    public boolean isTokenValid(String token, UserDetails userDetails) {

        final String username = extractUsername(token);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }



    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);

    }



    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);

    }



    private Claims extractAllClaims(String token) {

        return Jwts.parserBuilder()

                .setSigningKey(getPublicKey()) // CAMBIO: Validamos con la pública

                .build()

                .parseClaimsJws(token)

                .getBody();

    }



    private boolean isTokenExpired(String token) {

        return extractExpiration(token).before(new Date());

    }



    private Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);

    }



    // --- Métodos Helper para convertir el String Base64 a Objetos Key RSA ---



    private PrivateKey getPrivateKey() {

        try {

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyString);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(spec);

        } catch (Exception e) {

            throw new RuntimeException("Error cargando la clave privada", e);

        }

    }



    private PublicKey getPublicKey() {

        try {

            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePublic(spec);

        } catch (Exception e) {

            throw new RuntimeException("Error cargando la clave pública", e);

        }

    }

}