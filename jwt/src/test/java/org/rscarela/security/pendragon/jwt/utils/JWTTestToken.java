package org.rscarela.security.pendragon.jwt.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.rscarela.security.pendragon.jwt.JWTTokenProvider;

import java.util.Date;
import java.util.UUID;

import static org.rscarela.security.pendragon.jwt.utils.JWTTestValues.SECRET;

public class JWTTestToken {

    private final String uuid;
    private final String token;

    public static JWTTestToken forRandom() {
        return new JWTTestToken();
    }

    public static JWTTestToken forUsername(String username) {
        return new JWTTestToken(username);
    }

    public static JWTTestToken expired() {
        String uuid = UUID.randomUUID().toString();
        return new JWTTestToken(uuid, generateExpiredJWTToken(uuid));
    }

    private JWTTestToken(String uuid) {
        this.uuid = uuid;
        this.token = generateJWTToken(uuid);
    }

    private JWTTestToken(String uuid, String token) {
        this.uuid = uuid;
        this.token = token;
    }

    private JWTTestToken() {
        this(UUID.randomUUID().toString());
    }

    private static String generateJWTToken(String uuid) {
        return Jwts.builder()
                .setSubject(uuid)
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
    }

    private static String generateExpiredJWTToken(String uuid) {
        return Jwts.builder()
                .setSubject(uuid)
                .setExpiration(new Date(System.currentTimeMillis() - 1L))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
    }

    public String getUuid() {
        return uuid;
    }

    public String getToken() {
        return token;
    }

}
