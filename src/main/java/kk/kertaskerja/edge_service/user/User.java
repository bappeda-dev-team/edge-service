package kk.kertaskerja.edge_service.user;

import java.util.List;

public record User(
        String username,
        String firstName,
        String lastName,
        String kode_opd,
        String nip,
        List<String> roles
) {
}
