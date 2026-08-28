package kk.kertaskerja.edge_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record KeycloakError(
        String error,
        @JsonProperty("error_description")
        String errorDescription
) {}
