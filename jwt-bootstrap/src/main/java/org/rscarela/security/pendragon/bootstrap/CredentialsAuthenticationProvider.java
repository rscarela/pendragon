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
