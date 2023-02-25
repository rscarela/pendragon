package org.rscarela.security.pendragon.bootstrap;

import org.rscarela.security.pendragon.jwt.UserAuthentication;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUserProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Optional;

/**
 * Authentication provider based on user's username and password.
 *
 * This is the default behavior for extracting the UserAuthentication
 * based on Spring Security Context, by using the AuthenticatedUserProvider
 * implementation provided by the application domain.
 *
 * @see AuthenticatedUserProvider
 * @see AuthenticatedUser
 * @see UserAuthentication
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
@Named
public class CredentialsAuthenticationProvider implements AuthenticationProvider {

    private AuthenticatedUserProvider authenticatedUserProvider;

    @Inject
    public CredentialsAuthenticationProvider(AuthenticatedUserProvider authenticatedUserProvider) {
        this.authenticatedUserProvider = authenticatedUserProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        Optional<AuthenticatedUser> user = authenticatedUserProvider.findByCredentials(username, password);

        return user.isEmpty() ? null : new UserAuthentication(user.get());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
