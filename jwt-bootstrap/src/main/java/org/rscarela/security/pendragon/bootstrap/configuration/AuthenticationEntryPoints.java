package org.rscarela.security.pendragon.bootstrap.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

//@Named
public class AuthenticationEntryPoints implements HttpSecurityConfiguration {

//    private List<String> uris;
//
//    @Inject
//    public AuthenticationEntryPoints(@Value("${pendragon.jwt.web.auth.entrypoints}") List<String> uris) {
//        this.uris = uris;
//    }

    @Override
    public void apply(HttpSecurity security) throws Exception {
//        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry = security.authorizeRequests();
//
//        for(String uri : uris) {
//            urlRegistry.antMatchers(HttpMethod.POST, uri).permitAll();
//        }
    }

}
