package kk.kertaskerja.edge_service.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

public class CorsPropertiesTests {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues(
                    "kertaskerja.cors.allowed-origins=http://localhost:9876",
                    "kertaskerja.cors.allowed-methods=POST,GET,OPTIONS,DELETE",
                    "kertaskerja.cors.allowed-headers=*"
            );

    @Test
    void shouldBindPropertyFromYaml() {
        contextRunner.run(context -> {
            CorsProperties props = context.getBean(CorsProperties.class);
            assertThat(props.getAllowedOrigins()).contains("http://localhost:9876");
            assertThat(props.getAllowedMethods()).containsExactly("POST", "GET", "OPTIONS", "DELETE");
            assertThat(props.getAllowedHeaders()).containsExactly("*");
        });
    }

    @EnableConfigurationProperties(CorsProperties.class)
    static class TestConfig {
    }
}
