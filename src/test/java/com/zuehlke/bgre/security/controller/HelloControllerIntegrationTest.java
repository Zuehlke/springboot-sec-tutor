package com.zuehlke.bgre.security.controller;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class HelloControllerIntegrationTest {

    @BeforeClass
    public static void relaxHeaderRestrictions(){
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void hello_afterSuccessfulLogin_Ok() {
        ResponseEntity<String> loginResponse = restTemplate.postForEntity("/login", getEntityForJSON("{\"username\":\"admin\",\"password\":\"password123\"}"), String.class);
        assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
        String sessionCookie = loginResponse.getHeaders().get("Set-Cookie").iterator().next();

        HttpHeaders httpHeaders = getCORSHeaders();
        httpHeaders.add("Cookie", sessionCookie.split(";")[0]);
        HttpEntity<String> helloRequestEntity = new HttpEntity<>(httpHeaders);
        ResponseEntity<String> helloResponse = restTemplate.exchange("/hello", HttpMethod.GET, helloRequestEntity, String.class);

        assertEquals(HttpStatus.OK, helloResponse.getStatusCode());
        assertEquals("Welcome", helloResponse.getBody());
    }

    private HttpEntity<String> getEntityForJSON(String json) {
        HttpHeaders httpHeaders = getCORSHeaders();
        return new HttpEntity<>(json, httpHeaders);
    }

    private HttpHeaders getCORSHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("X-Requested-With", "JUNIT");
        httpHeaders.add("Origin", "http://myurl.com");
        return httpHeaders;
    }
}
