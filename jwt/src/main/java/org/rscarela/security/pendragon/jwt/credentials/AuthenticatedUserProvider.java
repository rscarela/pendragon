package org.rscarela.security.pendragon.jwt.credentials;

import java.util.Optional;

/**
 * Contract for the class responsible for loading authenticated users.
 *
 * An implementation for this class must provide actual behaviors for
 * loading the user domain class, represented by AuthenticatedUser.
 *
 * This class will be managed by Spring - please, make sure
 * its implementation is annotated either with @Named or
 * any other spring stereotype.
 *
 * @param <T> Domain class for the AuthenticatedUser
 *
 * @since 1.0.0
 * @author Renan Scarela
 */
public interface AuthenticatedUserProvider<T extends AuthenticatedUser> {

    /**
     * Loads an AuthenticatedUser by uuid.
     *
     * This method is used to load an already authenticated
     * user to provide a UserAuthentication.
     *
     * @param uuid - unique identifier used to load a user.
     * @return An optional that may contain the user to be loaded.
     */
    Optional<T> findByUuid(String uuid);

    /**
     * Loads an Authentication user by its username and password.
     *
     * This method is used when authenticating a user, loading it
     * by username and password.
     *
     * @param username - e.g. username, email, etc.
     * @param password - user password or key that grants access to the application.
     * @return
     */
    Optional<T> findByCredentials(String username, String password);

}
