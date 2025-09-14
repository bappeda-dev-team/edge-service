package kk.kertaskerja.edge_service.filter;

import kk.kertaskerja.edge_service.service.SessionService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@AllArgsConstructor
public class SessionToBearerFilter implements GlobalFilter, Ordered {

    private final SessionService sessionService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String sessionId = exchange.getRequest().getHeaders().getFirst("X-Session-Id");

        if (sessionId == null) {
            return chain.filter(exchange);
        }

        log.info("X-Session-Id received: {}", sessionId);

        return sessionService.resolveToken(sessionId)
                .flatMap(token -> {
                    log.info("Resolved access token: {}", token);

                    if (token != null) {
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .headers(httpHeaders -> httpHeaders.set("Authorization", "Bearer " + token))
                                .build();

                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(mutatedRequest)
                                .build();

                        return chain.filter(mutatedExchange);
                    }

                    return chain.filter(exchange);
                })
                .switchIfEmpty(Mono.defer(() -> {
                    // tidak ada token di redis -> log & teruskan (atau bisa langsung unauthorized)
                    log.warn("No token resolved for session {}, forwarding without Authorization header", sessionId);
                    return chain.filter(exchange);
                }));
    }

    @Override
    public int getOrder() {
        return -1;
    }

}
