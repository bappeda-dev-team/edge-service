package kk.kertaskerja.edge_service.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
public class SessionAuthenticationManager implements ReactiveAuthenticationManager {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtDecoder jwtDecoder;
    private final ObjectMapper objectMapper;

    public SessionAuthenticationManager(
            ReactiveStringRedisTemplate redisTemplate,
            @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String issuerUri,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri + "/protocol/openid-connect/certs").build();
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String sessionId = (String) authentication.getCredentials();

        return redisTemplate.opsForValue().get("session:" + sessionId)
                .flatMap(json -> {
                    try {
                        Map<String, Object> tokens = objectMapper.readValue(json, new TypeReference<>() {});
                        String accessToken = (String) tokens.get("access_token");

                        if (accessToken == null) {
                            return Mono.error(new BadCredentialsException("Access token not found in session"));
                        }

                        Jwt jwt = jwtDecoder.decode(accessToken);
                        Collection<GrantedAuthority> authorities =
                                List.of(new SimpleGrantedAuthority("ROLE_USER"));

                        // Cast eksplisit ke Authentication
                        Authentication auth = new UsernamePasswordAuthenticationToken(jwt.getSubject(), null, authorities);
                        return Mono.just(auth);
                    } catch (Exception e) {
                        return Mono.error(new BadCredentialsException("Invalid session data", e));
                    }
                })
                .switchIfEmpty(Mono.defer(() -> Mono.error(new BadCredentialsException("Invalid session"))));
    }
}
