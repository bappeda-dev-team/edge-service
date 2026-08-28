package kk.kertaskerja.edge_service.web;

import kk.kertaskerja.edge_service.dto.GatewayInfoResponse;
import kk.kertaskerja.edge_service.service.GatewayInfoService;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class GatewayInfoController {
    private final GatewayInfoService gatewayInfoService;

    public GatewayInfoController(GatewayInfoService gatewayInfoService) {
        this.gatewayInfoService = gatewayInfoService;
    }

    @GetMapping("/gateway-info")
    public Mono<GatewayInfoResponse> gatewayInfo(ServerHttpRequest request) {
        return gatewayInfoService.getGatewayInfo(request);
    }

}
