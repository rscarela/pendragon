package org.rscarela.security.pendragon.jwt.utils;

import org.rscarela.security.pendragon.jwt.credentials.UserCredentials;

public class SampleCredentials implements UserCredentials {

    private String username;
    private String password;

    protected SampleCredentials(){}

    public SampleCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

}
