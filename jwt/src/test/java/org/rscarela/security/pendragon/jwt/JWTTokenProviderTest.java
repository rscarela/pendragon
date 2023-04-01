package org.rscarela.security.pendragon.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUser;
import org.rscarela.security.pendragon.jwt.credentials.AuthenticatedUserProvider;
import org.rscarela.security.pendragon.jwt.utils.JWTTestToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.rscarela.security.pendragon.jwt.utils.JWTTestValues.EXPIRATION_TIME;
import static org.rscarela.security.pendragon.jwt.utils.JWTTestValues.HEADER_NAME;
import static org.rscarela.security.pendragon.jwt.utils.JWTTestValues.HEADER_PREFIX;
import static org.rscarela.security.pendragon.jwt.utils.JWTTestValues.SECRET;

@ExtendWith(MockitoExtension.class)
class JWTTokenProviderTest {

    private JWTTokenProvider jwtTokenProvider;

    @Mock private AuthenticatedUserProvider authenticatedUserProvider;
    @Mock private HttpServletResponse response;
    @Mock private HttpServletRequest request;

    @BeforeEach
    public void setup() {
        jwtTokenProvider = new JWTTokenProvider(
                authenticatedUserProvider,
                SECRET,
                EXPIRATION_TIME,
                HEADER_PREFIX,
                HEADER_NAME
        );
    }

    @Nested
    @DisplayName("Authentication generation")
    class GeneratesAuthentication {

        @Test
        @DisplayName("Must successfully set JWT Token to HttpServletResponse")
        public void mustSuccessfullySetJWTTokenToResponse() {
            jwtTokenProvider.addAuthentication(response, "username");

            verify(response, times(1)).addHeader(eq("Authorization"), any());
        }

    }

    @Nested
    @DisplayName("Authentication retrieval")
    class RetrievesAuthentication {

        @Test
        @DisplayName("Must return am instance of UserAuthentication when capable of loading authenticated user")
        public void mustReturnAnInstanceOfUserAuthentication() {
            JWTTestToken jwt = JWTTestToken.forRandom();
            when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt.getToken());
            when(authenticatedUserProvider.findByUuid(jwt.getUuid())).thenReturn(Optional.of((AuthenticatedUser) () -> jwt.getUuid()));

            Authentication authentication = jwtTokenProvider.getAuthentication(request);

            assertNotNull(authentication);
            assertTrue(authentication instanceof UserAuthentication);
        }

        @Test
        @DisplayName("Must return null if no Authorization header is provided on HttpServletRequest")
        public void mustReturnNullIfHeaderIsNotPresentOnRequest() {
            when(request.getHeader("Authorization")).thenReturn(null);

            Authentication authentication = jwtTokenProvider.getAuthentication(request);

            assertNull(authentication);
        }

        @Test
        @DisplayName("Must return null if token is malformed and unable to be parsed")
        public void mustReturnNullIfUnableToParseTheTokenDueMalformation() {
            when(request.getHeader("Authorization")).thenReturn("Bearer invalid");

            Authentication authentication = jwtTokenProvider.getAuthentication(request);

            assertNull(authentication);
        }

        @Test
        @DisplayName("Must return null if token is already expired")
        public void mustReturnNullIfProvidedTokenIsExpired() {
            JWTTestToken jwt = JWTTestToken.expired();
            when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt.getToken());

            Authentication authentication = jwtTokenProvider.getAuthentication(request);

            assertNull(authentication);
        }

        @Test
        @DisplayName("Must return null if no user can be loaded with unique identifier")
        public void mustReturnNullIfUnableToLoadUserWithParsedUuid() {
            JWTTestToken jwt = JWTTestToken.forRandom();
            when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt.getToken());

            Authentication authentication = jwtTokenProvider.getAuthentication(request);

            assertNull(authentication);
        }

    }

}