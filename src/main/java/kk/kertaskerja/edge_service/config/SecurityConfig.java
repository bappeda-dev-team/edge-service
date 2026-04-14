package kk.kertaskerja.edge_service.config;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.http.HttpCookie;
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
            ServerHttpRequest request = exchange.getRequest();

            HttpCookie sessionCookie = request.getCookies().getFirst("sessionId");
            if (sessionCookie != null && !sessionCookie.getValue().isBlank()) {
                String sessionId = sessionCookie.getValue();
                return Mono.just(
                        new UsernamePasswordAuthenticationToken(sessionId, sessionId));
            }

            // fallback
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

            // disable pop-up in browser
            response.getHeaders().remove("WWW-Authenticate");
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            // Tambahkan header CORS biar browser gak bego
            response.getHeaders().add("Access-Control-Allow-Origin", "*");
            response.getHeaders().add("Access-Control-Allow-Credentials", "true");

            // response unauthorized
            String body = """
                        {
                          "status": 401,
                          "error": "Unauthorized",
                          "message": "Invalid session"
                        }
                    """;

            DataBuffer buffer = response.bufferFactory()
                    .wrap(body.getBytes(StandardCharsets.UTF_8));

            return response.writeWith(Mono.just(buffer));
        });

        return http
                .cors(Customizer.withDefaults()) // pastikan cors jalan lebih dulu
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/auth/login").permitAll()
                        .pathMatchers("/api/docs/**").permitAll() // docs
                        .pathMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/api/webjars/swagger-ui/**",
                                "/webjars/swagger-ui/**",
                                "/v3/api-docs/**")
                        .permitAll() // docs ui
                        .pathMatchers("/actuator/health/ping").permitAll()
                        .anyExchange().authenticated())
                // disable pop-up in browser, extra
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> {
                            ServerHttpResponse response = exchange.getResponse();
                            response.setStatusCode(HttpStatus.UNAUTHORIZED);
                            response.getHeaders().remove("WWW-Authenticate");

                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                            String body = """
                                        {
                                          "status": 401,
                                          "error": "Unauthorized",
                                          "message": "Authentication required"
                                        }
                                    """;

                            DataBuffer buffer = response.bufferFactory()
                                    .wrap(body.getBytes(StandardCharsets.UTF_8));

                            return response.writeWith(Mono.just(buffer));
                        }))
                .addFilterAt(authWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .build();
    }

    @Bean
    CorsWebFilter corsWebFilter(CorsProperties corsProperties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(corsProperties.getAllowedOrigins());
        config.setAllowedHeaders(corsProperties.getAllowedHeaders());
        config.setAllowedMethods(corsProperties.getAllowedMethods());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
