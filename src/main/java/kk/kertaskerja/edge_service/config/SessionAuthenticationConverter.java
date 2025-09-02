package kk.kertaskerja.edge_service.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class SessionAuthenticationConverter implements ServerAuthenticationConverter {
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String sessionId = exchange.getRequest().getHeaders().getFirst("X-Session-Id");
        if (sessionId == null || sessionId.isBlank()) {
            return Mono.empty();
        }
        // username = sessionId, credentials = sessionId
        return Mono.just(new UsernamePasswordAuthenticationToken(sessionId, sessionId));
    }
}
