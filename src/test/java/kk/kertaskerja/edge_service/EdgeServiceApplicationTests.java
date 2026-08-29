package kk.kertaskerja.edge_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@ActiveProfiles("test")
class EdgeServiceApplicationTests {

	@MockitoBean
	ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Test
	void verifyThatSpringContextLoads() {
	}
}
