package org.rscarela.security.pendragon.jwt.credentials;

/**
 * Behavior definition for domain classes that
 * represents user's credentials.
 *
 * This is a very simple behavior that must provide
 * any content that makes sense in the application
 * context to be considered a username and a password.
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public interface UserCredentials {

    /**
     * @return username required for authentication.
     */
    String getUsername();

    /**
     * @return password required for authentication.
     */
    String getPassword();

}
