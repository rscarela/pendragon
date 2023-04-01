package org.rscarela.security.pendragon.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.rscarela.security.pendragon.jwt.utils.MockedServletInputStream;
import org.rscarela.security.pendragon.jwt.utils.SampleCredentials;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JWTAuthenticationFilterTest {

    private JWTAuthenticationFilter jwtAuthenticationFilter;

    @Mock private AuthenticationManager authenticationManager;
    @Mock private JWTTokenProvider jwtTokenProvider;

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;
    @Mock private Authentication authentication;

    @BeforeEach
    public void setup() {
        this.jwtAuthenticationFilter = new JWTAuthenticationFilter("/auth",
                authenticationManager,
                jwtTokenProvider,
                SampleCredentials.class);
    }

    @Test
    @DisplayName("Must successfully delegate authentication to Spring authentication manager")
    public void mustSuccessfullyAttemptToAuthenticate() throws IOException, ServletException {
        when(request.getInputStream()).thenReturn(new MockedServletInputStream(getCredentialsInput()));

        jwtAuthenticationFilter.attemptAuthentication(request, response);

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("Must successfully delegate the authentication to JWT Filter")
    public void mustSuccessfullyDelegateToJWTAuthenticationFilter() throws ServletException, IOException {
        when(authentication.getName()).thenReturn("name");

        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, authentication);

        verify(jwtTokenProvider, times(1)).addAuthentication(response, authentication.getName());
    }

    private String getCredentialsInput() throws JsonProcessingException {
        SampleCredentials credentials = new SampleCredentials("user", "pass");
        return new ObjectMapper().writeValueAsString(credentials);
    }

}