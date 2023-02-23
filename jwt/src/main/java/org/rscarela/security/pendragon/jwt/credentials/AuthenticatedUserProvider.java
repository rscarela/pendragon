package org.rscarela.security.pendragon.jwt.credentials;

import java.util.Optional;

public interface AuthenticatedUserProvider<T extends AuthenticatedUser> {

    Optional<T> findByUuid(String uuid);

    Optional<T> findByCredentials(String username, String password);

}
