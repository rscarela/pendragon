package org.rscarela.security.pendragon.jwt.credentials;

public interface CredentialsTypeProvider {

    Class<? extends UserCredentials> getCredentialsType();

}
