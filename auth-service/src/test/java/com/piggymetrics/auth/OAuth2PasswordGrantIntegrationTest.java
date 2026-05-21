package com.piggymetrics.auth;

import com.piggymetrics.auth.domain.User;
import com.piggymetrics.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class OAuth2PasswordGrantIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestRestTemplate restTemplate;

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private String tokenUrl;

    @BeforeEach
    public void setup() {
        userRepository.deleteAll();
        User user = new User();
        user.setUsername("testuser");
        user.setPassword(encoder.encode("testpassword"));
        userRepository.save(user);
        tokenUrl = "http://localhost:" + port + "/oauth2/token";
    }

    @Test
    public void shouldObtainTokenViaPasswordGrant() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "testuser");
        params.add("password", "testpassword");
        params.add("scope", "ui");
        params.add("client_id", "browser");
        params.add("client_secret", "browser");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().get("access_token"));
        assertEquals("Bearer", response.getBody().get("token_type"));
    }

    @Test
    public void shouldRejectInvalidCredentials() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "testuser");
        params.add("password", "wrongpassword");
        params.add("scope", "ui");
        params.add("client_id", "browser");
        params.add("client_secret", "browser");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        assertTrue(response.getStatusCode().is4xxClientError());
    }

    @Test
    public void shouldRejectNonExistentUser() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "nobody");
        params.add("password", "whatever");
        params.add("scope", "ui");
        params.add("client_id", "browser");
        params.add("client_secret", "browser");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        assertTrue(response.getStatusCode().is4xxClientError());
    }

    @Test
    public void shouldObtainTokenViaClientCredentials() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("scope", "server");
        params.add("client_id", "account-service");
        params.add("client_secret", "accsvc");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().get("access_token"));
        assertEquals("Bearer", response.getBody().get("token_type"));
    }

    @Test
    public void shouldServeJwkSet() {
        String jwksUrl = "http://localhost:" + port + "/oauth2/jwks";
        ResponseEntity<Map> response = restTemplate.getForEntity(jwksUrl, Map.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().get("keys"));
    }
}
