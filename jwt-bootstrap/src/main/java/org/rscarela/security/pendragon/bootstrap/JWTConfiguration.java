package org.rscarela.security.pendragon.bootstrap;

import org.rscarela.security.pendragon.bootstrap.configuration.URIConfigurations;
import org.rscarela.security.pendragon.jwt.JWTAuthenticationFilter;
import org.rscarela.security.pendragon.jwt.JWTFilter;
import org.rscarela.security.pendragon.jwt.JWTTokenProvider;
import org.rscarela.security.pendragon.jwt.credentials.CredentialsTypeProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.SecurityFilterChain;
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
public class JWTConfiguration {

    private final JWTTokenProvider tokenAuthenticationService;
    private final CredentialsTypeProvider credentialsTypeProvider;
    private final URIConfigurations uriConfigurations;

    @Inject
    public JWTConfiguration(JWTTokenProvider tokenAuthenticationService,
                            CredentialsTypeProvider credentialsTypeProvider,
                            URIConfigurations uriConfigurations) {
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.credentialsTypeProvider = credentialsTypeProvider;
        this.uriConfigurations = uriConfigurations;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable);

        httpSecurity.authorizeHttpRequests(auth -> {
            for (HttpMethod method : HttpMethod.values()) {
                auth.requestMatchers(uriConfigurations.getPermittedURIs().get(method)).permitAll();
                auth.requestMatchers(uriConfigurations.getDeniedURIs().get(method)).denyAll();
            }

            auth
                .anyRequest()
                .authenticated();
        });

        httpSecurity
                .addFilterBefore(new JWTAuthenticationFilter(uriConfigurations.getSignInPath(), authenticationManager, tokenAuthenticationService, credentialsTypeProvider.getCredentialsType()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JWTFilter(tokenAuthenticationService), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

}
