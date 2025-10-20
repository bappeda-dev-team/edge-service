package kk.kertaskerja.edge_service.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import reactor.core.publisher.Mono;

@Slf4j
@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {
    private final SessionAuthenticationManager sessionAuthManager;

    public SecurityConfig(SessionAuthenticationManager sessionAuthManager) {
        this.sessionAuthManager = sessionAuthManager;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        AuthenticationWebFilter authWebFilter = new AuthenticationWebFilter(sessionAuthManager);
        authWebFilter.setServerAuthenticationConverter(exchange -> {
            String sessionId = exchange.getRequest().getHeaders().getFirst("X-Session-Id");
            if (sessionId != null && !sessionId.isBlank()) {
                return Mono.just(new UsernamePasswordAuthenticationToken(sessionId, sessionId));
            }
            return Mono.empty();
        });

        // Pastikan failure handler tetap return 401 + header CORS
        authWebFilter.setAuthenticationFailureHandler((webFilterExchange, exception) -> {
            ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);

            // Tambahkan header CORS biar browser gak bego
            response.getHeaders().add("Access-Control-Allow-Origin", "*");
            response.getHeaders().add("Access-Control-Allow-Credentials", "true");

            return response.setComplete();
        });

        return http
                .cors(Customizer.withDefaults()) // pastikan cors jalan lebih dulu
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll() // preflight selalu diizinkan
                        .pathMatchers("/auth/login").permitAll()
                        .pathMatchers("/actuator/health/ping").permitAll()
                        .pathMatchers("/", "/*.css", "/*.js", "/favicon.ico", "/_next/**", "/assets/**", "/images/**", "/fonts/**", "/realisasi/**").permitAll()
                        .anyExchange().authenticated())
                .addFilterAt(authWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    CorsWebFilter corsWebFilter(CorsProperties corsProperties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(corsProperties.getAllowedOrigins());
        config.setAllowedHeaders(corsProperties.getAllowedHeaders());
        config.setAllowedMethods(corsProperties.getAllowedMethods());

        log.info("Configuring CORS with allowed origins: {}", corsProperties.getAllowedOrigins());
        log.info("Configuring CORS with allowed headers: {}", corsProperties.getAllowedHeaders());
        log.info("Configuring CORS with allowed methods: {}", corsProperties.getAllowedMethods());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
