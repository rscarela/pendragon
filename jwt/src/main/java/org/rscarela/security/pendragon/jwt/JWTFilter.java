package org.rscarela.security.pendragon.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 * Spring filter responsible for loading the current JWT authentication from SecurityContext.
 *
 * @see JWTTokenProvider
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public class JWTFilter extends GenericFilterBean {

    private JWTTokenProvider tokenAuthenticationService;

    public JWTFilter(JWTTokenProvider tokenAuthenticationService) {
        this.tokenAuthenticationService = tokenAuthenticationService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        Authentication authentication = tokenAuthenticationService.getAuthentication((HttpServletRequest) request);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

}
