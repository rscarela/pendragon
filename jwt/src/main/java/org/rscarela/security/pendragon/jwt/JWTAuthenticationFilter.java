package org.rscarela.security.pendragon.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.rscarela.security.pendragon.jwt.credentials.UserCredentials;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * JWT Filter responsible for protecting the authentication endpoint.
 *
 * It parses the credentials provided in the request to a valid instance
 * of UserCredentials and run the authentication process against them.
 *
 * @see JWTTokenProvider
 * @see UserCredentials
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public class JWTAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private JWTTokenProvider tokenAuthenticationService;
    private Class<? extends UserCredentials> credentialsType;

    public JWTAuthenticationFilter(String url,
                                   AuthenticationManager authManager,
                                   JWTTokenProvider tokenAuthenticationService,
                                   Class<? extends UserCredentials> credentialsType) {
        super(new AntPathRequestMatcher(url));
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.credentialsType = credentialsType;
        setAuthenticationManager(authManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        UserCredentials credentials = new ObjectMapper()
                .readValue(httpServletRequest.getInputStream(), credentialsType);

        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        credentials.getUsername(),
                        credentials.getPassword(),
                        Collections.emptyList()
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain,
            Authentication auth) throws IOException, ServletException {

        tokenAuthenticationService.addAuthentication(response, auth.getName());
    }

}
