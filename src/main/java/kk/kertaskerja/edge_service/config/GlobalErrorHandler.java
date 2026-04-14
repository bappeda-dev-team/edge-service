package kk.kertaskerja.edge_service.config;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Configuration
@Order(-2) // penting: override default
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        var response = exchange.getResponse();

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        if (ex instanceof org.springframework.web.server.ResponseStatusException rse) {
            status = (HttpStatus) rse.getStatusCode();
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
                    {
                      "status": %d,
                      "error": "%s",
                      "message": "%s"
                    }
                """.formatted(
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage() != null ? ex.getMessage() : "Unexpected error");

        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }
}
