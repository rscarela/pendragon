package org.rscarela.security.pendragon.bootstrap;

import org.rscarela.security.pendragon.bootstrap.configuration.URIConfigurations;
import org.rscarela.security.pendragon.jwt.JWTAuthenticationFilter;
import org.rscarela.security.pendragon.jwt.JWTFilter;
import org.rscarela.security.pendragon.jwt.JWTTokenProvider;
import org.rscarela.security.pendragon.jwt.credentials.CredentialsTypeProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.inject.Inject;

/**
 * This class is the configuration to be imported in a
 * Spring Boot application to have the JWT authentication
 * working.
 *
 * It's responsible for configuring HttpSecurity, by defining
 * all required filters, authentication endpoints and provided
 * permits and denies.
 *
 * @see CredentialsAuthenticationProvider
 * @see JWTTokenProvider
 * @see CredentialsTypeProvider
 * @see URIConfigurations
 */
@Configuration
@ComponentScan(basePackages = {"org.rscarela.security.pendragon.*"})
public class JWTConfiguration extends WebSecurityConfigurerAdapter {

    private final CredentialsAuthenticationProvider credentialsAuthenticationProvider;
    private final JWTTokenProvider tokenAuthenticationService;
    private final CredentialsTypeProvider credentialsTypeProvider;
    private final URIConfigurations uriConfigurations;

    @Inject
    public JWTConfiguration(CredentialsAuthenticationProvider credentialsAuthenticationProvider,
                            JWTTokenProvider tokenAuthenticationService,
                            CredentialsTypeProvider credentialsTypeProvider,
                            URIConfigurations uriConfigurations) {
        this.credentialsAuthenticationProvider = credentialsAuthenticationProvider;
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.credentialsTypeProvider = credentialsTypeProvider;
        this.uriConfigurations = uriConfigurations;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                .disable();

        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry expressionInterceptUrlRegistry = httpSecurity.authorizeRequests();

        for (HttpMethod method : HttpMethod.values()) {
            expressionInterceptUrlRegistry.antMatchers(uriConfigurations.getPermittedURIs().get(method)).permitAll();
            expressionInterceptUrlRegistry.antMatchers(uriConfigurations.getDeniedURIs().get(method)).denyAll();
        }

        expressionInterceptUrlRegistry
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(new JWTAuthenticationFilter(uriConfigurations.getSignInPath(), authenticationManager(), tokenAuthenticationService, credentialsTypeProvider.getCredentialsType()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JWTFilter(tokenAuthenticationService), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .authenticationProvider(credentialsAuthenticationProvider);
    }

}
