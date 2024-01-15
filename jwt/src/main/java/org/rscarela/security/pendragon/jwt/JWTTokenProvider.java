package org.rscarela.security.pendragon.jwt;

import io.jsonwebtoken.*;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUserProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;

import javax.inject.Inject;
import javax.inject.Named;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

/**
 * Provider responsible for orchestrating the JWT based authentication.
 *
 * This class is accountable for both generating the JWT token during authentication
 * and parsing an existing JWT for already authenticated users.
 *
 * It also carries all required configurations for the JWT to work, such as secret,
 * expiration time, header prefix and header name.
 *
 * @see AuthenticatedUserProvider
 *
 * @since 1.0.0
 * @author Renan Scarela
 */

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

    /**
     * Invoked during authentication, generates the JWT token and add it
     * to the request response.
     *
     * @param response - current HttpServletResponse
     * @param username - Username that identifies the user that is authenticating
     */
    public void addAuthentication(HttpServletResponse response, String username) {
        String JWT = Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        response.addHeader(headerName, headerPrefix + " " + JWT);
    }

    /**
     * Load an Authentication instance for the provided JWT Token.
     *
     * Token will be parsed to retrieve its unique identifier. Afterwards,
     * existing AuthenticationUserProvider will be invoked to retrieve the
     * entity for the authenticated user, and will use it to instantiate the
     * authentication.
     *
     * @param request - current HttpServletRequest
     * @return UserAuthentication parsed from current JWT token
     */
    public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(headerName);

        if (token == null) return null;

        String uuid = getParsedUuid(token);

        if (uuid == null) return null;

        Optional<AuthenticatedUser> user = authenticatedUserProvider.findByUuid(uuid);

        return user.isEmpty() ? null : new UserAuthentication(user.get());
    }

    /**
     * Parses the Authorization header to retrieve the JWT token content.
     *
     * If already expired or malformed, null is returned and a 403 status
     * will be raised.
     *
     * @param token
     * @return current JWT content
     */
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
