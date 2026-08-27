package kk.kertaskerja.edge_service.gateway_info;

import java.util.List;

public record GatewayRouteResponse(
        String id,
        List<GatewayPredicateResponse> predicates
) {}
