package org.rscarela.security.pendragon.jwt.credentials;

/**
 * Simple class responsible for returning the class type
 * to be used as UserCredentials. This will be used during
 * authentication to parse user credentials appropriately.
 *
 * This class will be managed by Spring - please, make sure
 * its implementation is annotated either with @Named or
 * any other spring stereotype.
 *
 * @see UserCredentials
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public interface CredentialsTypeProvider {

    /**
     * @return Class of the domain implementation of UserCredentials.
     */
    Class<? extends UserCredentials> getCredentialsType();

}
