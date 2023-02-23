package org.rscarela.security.pendragon.jwt;

import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

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

    public <T> T getUser() {
        return (T) user;
    }
}
