package kk.kertaskerja.edge_service.dto;

import java.util.List;

public record GatewayServiceResponse(
        String name,
        String uri,
        List<GatewayRouteResponse> routes
) {}
