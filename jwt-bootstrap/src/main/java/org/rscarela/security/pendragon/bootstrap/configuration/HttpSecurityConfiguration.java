package org.rscarela.security.pendragon.bootstrap.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface HttpSecurityConfiguration {

    void apply(HttpSecurity security) throws Exception;

}
