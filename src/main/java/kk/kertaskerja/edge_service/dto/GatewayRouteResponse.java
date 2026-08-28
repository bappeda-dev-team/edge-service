package kk.kertaskerja.edge_service.dto;

import java.util.List;

public record GatewayRouteResponse(
        String id,
        List<GatewayPredicateResponse> predicates
) {}
