package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = {
        "auth.security.hmacKey=integration-test-hmac-key",
        "auth.token.stateFile=target/test-data/it-ratelimit.json",
        "auth.ratelimit.maxRequests=10",
        "auth.ratelimit.windowSeconds=60"
})
@AutoConfigureMockMvc
class RateLimitIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void eleventhRequestInWindowIsRateLimited() throws Exception {
        MvcResult tokenResult = mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"bob","password":"bob-pass-123"}"""))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = JsonCodec.mapper().readTree(tokenResult.getResponse().getContentAsByteArray());
        String access = body.get("access_token").asText();

        for (int i = 1; i <= 10; i++) {
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + access))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + access))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("rate_limited"));
    }
}
