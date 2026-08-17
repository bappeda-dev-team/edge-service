package kk.kertaskerja.edge_service.filter;

import kk.kertaskerja.edge_service.service.SessionService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@AllArgsConstructor
public class SessionToBearerFilter implements GlobalFilter, Ordered {

    private final SessionService sessionService;

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/auth/login",
            "/auth/logout");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // PUBLIC PATH, BYPASS SESSION ID
        if (PUBLIC_PATHS.contains(path)) {
            return chain.filter(exchange);
        }

        String sessionId = exchange.getRequest().getCookies().getFirst("sessionId") != null
                ? exchange.getRequest().getCookies().getFirst("sessionId").getValue()
                : null;

        if (sessionId == null || sessionId.isBlank()) {
            return chain.filter(exchange);
        }

        return sessionService.resolveToken(sessionId)
                .flatMap(token -> {
                    if (token != null) {
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .headers(httpHeaders -> httpHeaders.set(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                                .build();

                        return chain.filter(exchange.mutate()
                                .request(mutatedRequest)
                                .build());
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }

    @Override
    public int getOrder() {
        return -1;
    }

}
