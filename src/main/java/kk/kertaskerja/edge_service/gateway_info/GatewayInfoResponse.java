package kk.kertaskerja.edge_service.gateway_info;

import java.util.List;

public record GatewayInfoResponse(
        String name,
        String baseUrl,
        String status,
        List<GatewayServiceResponse> services
) {}
