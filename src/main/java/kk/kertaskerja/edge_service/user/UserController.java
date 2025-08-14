package kk.kertaskerja.edge_service.user;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class UserController {
    // OIDC User Info
    @GetMapping("user")
    public Mono<User> getUser(@AuthenticationPrincipal OidcUser oidcUser) {
        var user = new User(
                oidcUser.getPreferredUsername(),
                oidcUser.getGivenName(),
                oidcUser.getClaim("kode_opd"),
                oidcUser.getClaim("nip"),
                oidcUser.getClaimAsStringList("roles")
        );
        return Mono.just(user);
    }

    // JWT User Info
    @GetMapping("user-info")
    public Mono<User> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        var user = new User(
                jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("given_name"),
                jwt.getClaimAsString("kode_opd"),
                jwt.getClaimAsString("nip"),
                jwt.getClaimAsStringList("roles")
        );
        return Mono.just(user);
    }
}
