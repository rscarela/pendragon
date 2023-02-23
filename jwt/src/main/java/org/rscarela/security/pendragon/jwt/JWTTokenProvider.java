package org.rscarela.security.pendragon.jwt;

import io.jsonwebtoken.*;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUserProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

@Named
public class JWTTokenProvider {

    private AuthenticatedUserProvider authenticatedUserProvider;
    private String secret;
    private Long expirationTime;
    private String headerPrefix;
    private String headerName;

    @Inject
    public JWTTokenProvider(AuthenticatedUserProvider authenticatedUserProvider,
                            @Value("${pendragon.jwt.secret}") String secret,
                            @Value("${pendragon.jwt.expiration:860000000}") Long expirationTime,
                            @Value("${pendragon.jwt.header.prefix:Bearer}") String headerPrefix,
                            @Value("${pendragon.jwt.header.name:Authorization}") String headerName) {
        this.authenticatedUserProvider = authenticatedUserProvider;
        this.secret = secret;
        this.expirationTime = expirationTime;
        this.headerPrefix = headerPrefix;
        this.headerName = headerName;
    }

    public void addAuthentication(HttpServletResponse response, String username) {
        String JWT = Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        response.addHeader(headerName, headerPrefix + " " + JWT);
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(headerName);

        if (token == null) return null;

        String uuid = getParsedUuid(token);

        if (uuid == null) return null;

        Optional<AuthenticatedUser> user = authenticatedUserProvider.findByUuid(uuid);

        return user.isEmpty() ? null : new UserAuthentication(user.get());
    }

    private String getParsedUuid(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token.replace(headerPrefix, ""))
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            System.out.println("Expired token");
        } catch (UnsupportedJwtException | MalformedJwtException e) {
            System.out.println("Invalid token");
        }

        return null;
    }

}
