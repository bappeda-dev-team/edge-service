package kk.kertaskerja.edge_service.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Component
public class SessionService {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public SessionService(ReactiveStringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    public Mono<String> resolveToken(String sessionId) {
        String key = "session:" + sessionId;
        log.info("SESSION SERVICE resolving key: {}", key);

        return redisTemplate.opsForValue()
                .get(key)
                .doOnSubscribe(s -> log.debug("Subscribe to redis GET for key {}", key))
                .doOnSuccess(json -> {
                    if (json == null) {
                        log.warn("Redis returned no value for key {}", key);
                    } else {
                        log.info("token from redis raw json for {}: {}", key, json);
                    }
                })
                .flatMap(json -> {
                    if (json == null) {
                        // complete empty => no token
                        return Mono.empty();
                    }
                    try {
                        Map<String, Object> tokens = objectMapper.readValue(json, new TypeReference<>() {});
                        String token = (String) tokens.get("access_token");
                        if (token == null) {
                            log.warn("No access_token field in session payload for key {}", key);
                            return Mono.empty();
                        }
                        return Mono.just(token);
                    } catch (Exception e) {
                        log.error("Failed to parse JSON for key {}: {}", key, e.getMessage(), e);
                        return Mono.empty(); // don't fail chain, just treat as no token
                    }
                })
                .doOnError(e -> log.error("Redis GET error for key {}: {}", key, e.getMessage(), e))
                .onErrorResume(e -> Mono.empty()); // tolerate redis parsing errors
    }

}
