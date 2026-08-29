package kk.kertaskerja.edge_service.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nonnull;
import kk.kertaskerja.edge_service.dto.ApiErrorResponse;
import kk.kertaskerja.edge_service.user.InvalidSessionException;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Configuration
@Order(-2)
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper objectMapper;

    public GlobalErrorHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    @Nonnull
    public Mono<Void> handle(
            ServerWebExchange exchange,
            @NonNull Throwable ex
    ) {
        ServerHttpResponse response = exchange.getResponse();

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "Unexpected error";

        if (ex instanceof InvalidSessionException) {
            status = HttpStatus.UNAUTHORIZED;
            message = "Invalid session";

            ResponseCookie cookie = ResponseCookie.from("sessionId", "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(Duration.ZERO)
                    .sameSite("Lax")
                    .build();

            response.addCookie(cookie);
        }


        if (ex instanceof ResponseStatusException rse) {
            status = HttpStatus.valueOf(rse.getStatusCode().value());

            if (rse.getReason() != null && !rse.getReason().isBlank()) {
                message = rse.getReason();
            }
        }

        ApiErrorResponse errorResponse = new ApiErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                message
        );

        response.setStatusCode(status);
        response.getHeaders().setContentType(
                MediaType.APPLICATION_JSON
        );

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);

            DataBuffer buffer = response.bufferFactory()
                    .wrap(bytes);

            return response.writeWith(Mono.just(buffer));

        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }
    }
}
