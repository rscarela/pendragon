package org.rscarela.security.pendragon.bootstrap.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class AuthenticationIgnore implements HttpSecurityConfiguration {

    @Override
    public void apply(HttpSecurity security) throws Exception {

    }
}
