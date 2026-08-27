package kk.kertaskerja.edge_service.service;

import org.springframework.beans.factory.annotation.Value;
import kk.kertaskerja.edge_service.gateway_info.GatewayInfoResponse;
import kk.kertaskerja.edge_service.gateway_info.GatewayPredicateResponse;
import kk.kertaskerja.edge_service.gateway_info.GatewayRouteResponse;
import kk.kertaskerja.edge_service.gateway_info.GatewayServiceResponse;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

// GatewayInfoService.java
@Service
public class GatewayInfoService {
    private final RouteDefinitionLocator routeDefinitionLocator;
    private final String applicationName;

    public GatewayInfoService(
            RouteDefinitionLocator routeDefinitionLocator,
            @Value("${spring.application.name:edge-service}") String applicationName
    ) {
        this.routeDefinitionLocator = routeDefinitionLocator;
        this.applicationName = applicationName;
    }

    public Mono<GatewayInfoResponse> getGatewayInfo(ServerHttpRequest request) {
        return routeDefinitionLocator.getRouteDefinitions()
                .collectList()
                .map(routeDefinitions -> new GatewayInfoResponse(
                        applicationName,
                        baseUrl(request),
                        "UP",
                        groupServices(routeDefinitions)
                ));
    }

    private List<GatewayServiceResponse> groupServices(
            List<RouteDefinition> routeDefinitions
    ) {
        return routeDefinitions.stream()
                .collect(Collectors.groupingBy(
                        route -> route.getUri().toString(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ))
                .entrySet()
                .stream()
                .map(entry -> new GatewayServiceResponse(
                        serviceName(entry.getValue().getFirst()),
                        entry.getKey(),
                        entry.getValue().stream()
                                .map(this::toRoute)
                                .toList()
                ))
                .toList();
    }

    private GatewayRouteResponse toRoute(RouteDefinition route) {
        return new GatewayRouteResponse(
                route.getId(),
                route.getPredicates().stream()
                        .map(predicate -> new GatewayPredicateResponse(
                                predicate.getName(),
                                predicate.getArgs().values().stream()
                                        .findFirst()
                                        .orElse("")
                        ))
                        .toList()
        );
    }

    private String serviceName(RouteDefinition route) {
        URI uri = route.getUri();

        if ("lb".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) {
            return uri.getHost();
        }

        return uri.toString();
    }

    private String baseUrl(ServerHttpRequest request) {
        URI uri = request.getURI();

        return UriComponentsBuilder.newInstance()
                .scheme(uri.getScheme())
                .host(uri.getHost())
                .port(uri.getPort())
                .build()
                .toUriString();
    }
}
