package kk.kertaskerja.edge_service.user;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@SuppressWarnings("unused")
public class UserController {
    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtDecoder jwtDecoder;
    private final ObjectMapper objectMapper;


    public UserController(ReactiveStringRedisTemplate redisTemplate,
                          @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String issuerUri,
                          ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri + "/protocol/openid-connect/certs").build();
        this.objectMapper = objectMapper;
    }
    // OIDC User Info
    @GetMapping("user")
    public Mono<User> getUser(@AuthenticationPrincipal OidcUser oidcUser) {
        var user = new User(
                oidcUser.getPreferredUsername(),
                oidcUser.getGivenName(),
                oidcUser.getClaim("kode_opd"),
                oidcUser.getClaim("nip"),
                oidcUser.getClaimAsStringList("roles"));
        return Mono.just(user);
    }

    // JWT User Info
    @GetMapping("user-info")
    public Mono<User> getUserInfo(@RequestHeader("X-Session-Id") String sessionId) {
        return redisTemplate.opsForValue().get("session:" + sessionId)
                .flatMap(json -> {
                    try {
                        // Parse JSON tokens dari Redis
                        Map<String, Object> tokens = objectMapper.readValue(json, new TypeReference<>() {});
                        String accessToken = (String) tokens.get("access_token");

                        if (accessToken == null) {
                            return Mono.error(new RuntimeException("Access token not found"));
                        }

                        // Decode JWT
                        Jwt jwt = jwtDecoder.decode(accessToken);

                        // Buat User dari claim
                        var user = new User(
                                jwt.getClaimAsString("preferred_username"),
                                jwt.getClaimAsString("given_name"),
                                jwt.getClaimAsString("kode_opd"),
                                jwt.getClaimAsString("nip"),
                                jwt.getClaimAsStringList("roles")
                        );

                        return Mono.just(user);
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Failed to parse session JWT", e));
                    }
                })
                .switchIfEmpty(Mono.error(new RuntimeException("Invalid sessionId")));
    }

    @GetMapping("token-info")
    public Mono<String> showToken(@RequestHeader("X-Session-Id") String sessionId) {
        return redisTemplate.opsForValue().get("session:" + sessionId)
                .flatMap(json -> {
                    try {
                        // Parse JSON tokens dari Redis
                        Map<String, Object> tokens = objectMapper.readValue(json, new TypeReference<>() {});
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
}
