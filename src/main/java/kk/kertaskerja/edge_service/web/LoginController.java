package kk.kertaskerja.edge_service.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
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

    public record LoginRequest(String username, String password) {}

    @PostMapping("/login")
    public Mono<Map<String, Object>> login(@RequestBody LoginRequest loginRequest) {
        String tokenUrl = issuerUri + "/protocol/openid-connect/token";

        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "password")
                        .with("client_id", clientId)
                        .with("client_secret", clientSecret)
                        .with("username", loginRequest.username())
                        .with("password", loginRequest.password())
                )
                .exchangeToMono(response ->
                        response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                )
                .flatMap(tokens -> {
                    // generate sessionId
                    String sessionId = UUID.randomUUID().toString();

                    try {
                        // serialize Map -> JSON String
                        String jsonTokens = new ObjectMapper().writeValueAsString(tokens);

                        // simpan JSON string di redis
                        return redisTemplate.opsForValue()
                                .set("session:" + sessionId, jsonTokens)
                                .thenReturn(Map.of("sessionId", sessionId));
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                });
    }

    public record RefreshRequest(String sessionId) {}

    @PostMapping("/refresh")
    public Mono<Map<String, Object>> refresh(@RequestBody RefreshRequest refreshRequest) {
        String tokenUrl = issuerUri + "/protocol/openid-connect/token";

        return redisTemplate.opsForHash().get("tokens", refreshRequest.sessionId)
                .cast(Map.class)
                .flatMap(savedTokens -> {
                    String refreshToken = (String) savedTokens.get("refresh_token");

                    return webClient.post()
                            .uri(tokenUrl)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .body(BodyInserters.fromFormData("grant_type", "password")
                                    .with("client_id", clientId)
                                    .with("client_secret", clientSecret)
                                    .with("refresh_token", refreshToken)
                            )
                            .retrieve()
                            .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                            })
                            .flatMap(newTokens -> {
                                newTokens.put("sessionId", refreshRequest.sessionId);
                                return redisTemplate.opsForHash()
                                        .put("tokens", refreshRequest.sessionId, newTokens)
                                        .thenReturn(newTokens);
                            });
                });
    }

    @PostMapping("/logout")
    public Mono<String> logout(@RequestParam String sessionId) {
        return redisTemplate.opsForHash().remove("tokens", sessionId)
                .flatMap(count -> {
                    if (count > 0) {
                        return Mono.just("Session " + sessionId + " removed");
                    } else {
                        return Mono.error(new RuntimeException("Session not found"));
                    }
                });
    }
}
