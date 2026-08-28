package kk.kertaskerja.edge_service.dto;

import java.util.List;

public record User(
        String username,
        String firstName,
        String kode_opd,
        String nip,
        List<String> roles
) {
}
