package kk.kertaskerja.edge_service.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import kk.kertaskerja.edge_service.user.InvalidSessionException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import reactor.core.publisher.Mono;

@SpringBootTest
@AutoConfigureWebTestClient
class SecurityConfigTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private SessionAuthenticationManager sessionAuthManager;

    @Test
    void shouldReturnInvalidSessionExceptionWhenSessionIsInvalid() {

        String sessionId = "invalid-session-id";

        when(sessionAuthManager.authenticate(any(Authentication.class)))
                .thenReturn(
                        Mono.error(
                                new InvalidSessionException()));

        webTestClient
                .get()
                .uri("/api/test")
                .cookie("sessionId", sessionId)
                .exchange()
                .expectStatus()
                .isUnauthorized()
                .expectHeader()
                .contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.status")
                .isEqualTo(401)
                .jsonPath("$.error")
                .isEqualTo("Unauthorized")
                .jsonPath("$.message")
                .isEqualTo("Invalid session");
    }
}
