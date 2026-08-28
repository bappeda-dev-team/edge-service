package kk.kertaskerja.edge_service.dto;

public record ApiErrorResponse(
        int status,
        String error,
        String message
) {
}
