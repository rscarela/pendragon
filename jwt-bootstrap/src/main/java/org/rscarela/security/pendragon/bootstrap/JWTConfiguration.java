package org.rscarela.security.pendragon.bootstrap;

import org.rscarela.security.pendragon.jwt.JWTAuthenticationFilter;
import org.rscarela.security.pendragon.jwt.JWTFilter;
import org.rscarela.security.pendragon.jwt.JWTTokenProvider;
import org.rscarela.security.pendragon.jwt.credentials.CredentialsTypeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@ComponentScan(basePackages = {"org.rscarela.security.pendragon.*"})
public class JWTConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private CredentialsAuthenticationProvider credentialsAuthenticationProvider;

    @Autowired
    private JWTTokenProvider tokenAuthenticationService;

    @Autowired
    private CredentialsTypeProvider credentialsTypeProvider;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/auth").permitAll()
                .antMatchers(HttpMethod.POST, "/auth/signup").permitAll()
                .antMatchers(HttpMethod.GET, "/graphql").permitAll()
                .antMatchers(HttpMethod.POST, "/graphql").permitAll()
                .antMatchers(HttpMethod.GET, "/graphiql*").permitAll()
                .antMatchers(HttpMethod.POST, "/graphiql*").permitAll()
                .antMatchers(HttpMethod.GET, "/vendor/**").permitAll()
                .antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(new JWTAuthenticationFilter("/auth", authenticationManager(), tokenAuthenticationService, credentialsTypeProvider.getCredentialsType()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JWTFilter(tokenAuthenticationService), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .authenticationProvider(credentialsAuthenticationProvider);
    }

}
