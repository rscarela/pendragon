package org.rscarela.security.pendragon.jwt;

import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

/**
 * Representation of a UserAuthentication, which may be injected
 * in any controller (either in its attributes or method params),
 * for any authenticated user.
 *
 * This class also provides easy access to the domain class used
 * as an AuthenticatedUser.
 *
 * In its current state, this is a very simplified representation.
 * There are no authority controls and getters are simplified to
 * return the most basic information of the user.
 *
 * @see AuthenticatedUser
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public class UserAuthentication implements Authentication {

    private AuthenticatedUser user;
    private boolean authenticated;

    public UserAuthentication(AuthenticatedUser user) {
        this.user = user;
        this.authenticated = user != null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return user;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return user.getUuid();
    }

    /**
     * Convenience method that returns the AuthenticatedUser already parsed
     * to the domain class used as its instance.
     *
     * @return AuthenticatedUser parsed to its actual domain implementation.
     * @param <T> Actual type of the AuthenticatedUser implementation
     */
    public <T> T getUser() {
        return (T) user;
    }
}
