package kk.kertaskerja.edge_service;

import kk.kertaskerja.edge_service.config.CorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CorsProperties.class)
public class EdgeServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(EdgeServiceApplication.class, args);
	}

}
