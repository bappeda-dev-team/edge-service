package kk.kertaskerja.edge_service.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import kk.kertaskerja.edge_service.token.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@SuppressWarnings("unused")
public class LoginController {
    private final WebClient webClient;
    private final ReactiveRedisTemplate<String, Object> redisTemplate;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    String clientSecret;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    String issuerUri;

    public LoginController(WebClient.Builder webClientBuilder, ReactiveRedisTemplate<String, Object> redisTemplate) {
        this.webClient = webClientBuilder.build();
        this.redisTemplate = redisTemplate;
    }

    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, Object>>> login(@RequestBody LoginRequest loginRequest) {
        String tokenUrl = issuerUri + "/protocol/openid-connect/token";

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "password")
                        .with("client_id", clientId)
                        .with("client_secret", clientSecret)
                        .with("username", loginRequest.username())
                        .with("password", loginRequest.password()))
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                        });
                    } else {
                        return response.bodyToMono(String.class)
                                .flatMap(body -> Mono.error(new RuntimeException("Login gagal: " + body)));
                    }
                })
                .flatMap(tokens -> {
                    if (!tokens.containsKey("access_token")) {
                        return Mono.error(new RuntimeException("Login gagal: tidak ada access_token"));
                    }
                    String sessionId = UUID.randomUUID().toString();

                    try {
                        String jsonTokens = new ObjectMapper().writeValueAsString(tokens);

                        return redisTemplate.opsForValue()
                                .set("session:" + sessionId, jsonTokens, Duration.ofHours(5))
                                .thenReturn(buildLoginResponse(sessionId));
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

    @PostMapping("/refresh")
    public Mono<TokenResponse> refresh(@RequestHeader("X-Session-Id") String sessionId) {
        String tokenUrl = issuerUri + "/protocol/openid-connect/token";

        return redisTemplate.opsForValue()
                .get("session:" + sessionId)
                .cast(String.class)
                .flatMap(json -> {
                    try {
                        TokenResponse savedTokens = new ObjectMapper().readValue(json, TokenResponse.class);

                        String refreshToken = savedTokens.refreshToken();

                        return webClient.post()
                                .uri(tokenUrl)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .body(BodyInserters.fromFormData("grant_type", "refresh_token")
                                        .with("client_id", clientId)
                                        .with("client_secret", clientSecret)
                                        .with("refresh_token", refreshToken))
                                .exchangeToMono(response -> {
                                    if (response.statusCode().is2xxSuccessful()) {
                                        return response.bodyToMono(TokenResponse.class);
                                    } else {
                                        return response.bodyToMono(String.class)
                                                .flatMap(body -> Mono
                                                        .error(new RuntimeException("Login gagal: " + body)));
                                    }
                                })
                                .flatMap(newTokens -> {
                                    if (newTokens.accessToken() == null) {
                                        return Mono.error(new RuntimeException("Login gagal: tidak ada access_token"));
                                    }
                                    try {
                                        String newJson = new ObjectMapper().writeValueAsString(newTokens);
                                        return redisTemplate.opsForValue()
                                                .set("session:" + sessionId, newJson, Duration.ofHours(5))
                                                .thenReturn(newTokens);
                                    } catch (Exception e) {
                                        return Mono.error(e);
                                    }
                                });

                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

    @PostMapping("/logout")
    public Mono<String> logout(@RequestHeader("X-Session-Id") String sessionId) {
        return redisTemplate.opsForValue().delete("session:" + sessionId)
                .flatMap(success -> {
                    if (success) {
                        return Mono.just("Session " + sessionId + " removed");
                    } else {
                        return Mono.error(new RuntimeException("Session not found"));
                    }
                });
    }

    private ResponseEntity<Map<String, Object>> buildLoginResponse(String sessionId) {
        ResponseCookie cookie = ResponseCookie.from("sessionId", sessionId)
                .httpOnly(true)
                .sameSite("Lax")
                .path("/")
                // .secure(true) // AKTIFKAN kalau sudah HTTPS
                .maxAge(Duration.ofHours(5))
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of("sessionId", sessionId));
    }
}
