package kk.kertaskerja.edge_service.user;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import kk.kertaskerja.edge_service.dto.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {
    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtDecoder jwtDecoder;
    private final ObjectMapper objectMapper;

    public UserController(
            ReactiveStringRedisTemplate redisTemplate,
            @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String issuerUri,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri + "/protocol/openid-connect/certs").build();
        this.objectMapper = objectMapper;
    }

    // JWT User Info
    @GetMapping("user-info")
    public Mono<User> getUserInfoAlt(ServerHttpRequest request) {
        String sessionId = getSessionId(request);

        // Tidak ada session
        if (sessionId == null || sessionId.isBlank()) {
            return Mono.error(
                    new ResponseStatusException(
                            HttpStatus.UNAUTHORIZED,
                            "Authentication required"));
        }

        final String key = "session:" + sessionId;

        return redisTemplate.opsForValue()
                .get(key)
                .switchIfEmpty(
                        Mono.error(
                                new ResponseStatusException(
                                        HttpStatus.UNAUTHORIZED,
                                        "Invalid session")))
                .flatMap(json -> {
                    try {
                        Map<String, Object> tokens = objectMapper.readValue(
                                json,
                                new TypeReference<>() {
                                });

                        String accessToken = (String) tokens.get("access_token");

                        if (accessToken == null || accessToken.isBlank()) {
                            return Mono.error(
                                    new ResponseStatusException(
                                            HttpStatus.UNAUTHORIZED,
                                            "Invalid session"));
                        }

                        Jwt jwt = jwtDecoder.decode(accessToken);

                        User user = new User(
                                jwt.getClaimAsString(
                                        "preferred_username"),
                                jwt.getClaimAsString(
                                        "given_name"),
                                jwt.getClaimAsString(
                                        "kode_opd"),
                                jwt.getClaimAsString(
                                        "nip"),
                                jwt.getClaimAsStringList("roles"));

                        return Mono.just(user);

                    } catch (Exception e) {
                        return Mono.error(
                                new ResponseStatusException(
                                        HttpStatus.UNAUTHORIZED,
                                        "Invalid session"));
                    }
                });
    }

    // GET REAL TOKEN FROM SESSION ID
    @GetMapping("token-info")
    public Mono<String> showToken(ServerHttpRequest request) {
        String sessionId = getSessionId(request);

        // Tidak ada session
        if (sessionId == null || sessionId.isBlank()) {
            return Mono.error(
                    new ResponseStatusException(
                            HttpStatus.UNAUTHORIZED,
                            "Authentication required"));
        }

        return redisTemplate.opsForValue().get("session:" + sessionId)
                .flatMap(json -> {
                    try {
                        // Parse JSON tokens dari Redis
                        Map<String, Object> tokens = objectMapper.readValue(json, new TypeReference<>() {
                        });
                        String accessToken = (String) tokens.get("access_token");

                        if (accessToken == null) {
                            return Mono.error(new RuntimeException("Access token not found"));
                        }

                        return Mono.just(accessToken);
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Failed to parse session JWT", e));
                    }
                })
                .switchIfEmpty(Mono.error(new RuntimeException("Invalid sessionId")));
    }

    public String getSessionId(ServerHttpRequest request) {
        String sessionId = null;

        // Prioritas cookie
        HttpCookie sessionCookie = request.getCookies().getFirst("sessionId");

        if (sessionCookie != null && !sessionCookie.getValue().isBlank()) {
            sessionId = sessionCookie.getValue();
        }

        // Fallback X-Session-Id
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = request.getHeaders().getFirst("X-Session-Id");
        }

        return sessionId;
    }
}
