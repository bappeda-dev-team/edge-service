package kk.kertaskerja.edge_service.config;

import org.springframework.http.HttpCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class SessionAuthenticationConverter implements ServerAuthenticationConverter {
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        // try from header
        String sessionId = resolveSessionId(exchange);

        // Kalau tetap tidak ada → tidak authenticate
        if (sessionId == null || sessionId.isBlank()) {
            return Mono.empty();
        }
        // username = sessionId, credentials = sessionId
        return Mono.just(new UsernamePasswordAuthenticationToken(sessionId, sessionId));
    }

    private String resolveSessionId(ServerWebExchange exchange) {
        // 1. Prioritaskan cookie
        HttpCookie cookie = exchange.getRequest()
                .getCookies()
                .getFirst("sessionId");

        if (cookie != null && !cookie.getValue().isBlank()) {
            return cookie.getValue();
        }

        // 2. Fallback ke header
        String header = exchange.getRequest()
                .getHeaders()
                .getFirst("X-Session-Id");

        if (header != null && !header.isBlank()) {
            return header;
        }

        return null;
    }

}
