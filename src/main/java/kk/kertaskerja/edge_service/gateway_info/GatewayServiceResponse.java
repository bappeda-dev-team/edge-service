package kk.kertaskerja.edge_service.gateway_info;

import java.util.List;

public record GatewayServiceResponse(
        String name,
        String uri,
        List<GatewayRouteResponse> routes
) {}
