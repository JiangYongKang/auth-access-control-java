package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(properties = {
        "auth.security.hmacKey=integration-test-hmac-key",
        "auth.token.stateFile=target/test-data/it-refresh-expiry.json",
        "auth.token.accessTtlSeconds=60",
        "auth.token.refreshTtlSeconds=120"
})
@AutoConfigureMockMvc
class RefreshExpiryIntegrationTest {

    static class MutableClock extends Clock {
        private volatile long seconds = 1_700_000_000L;

        void advance(long delta) {
            this.seconds += delta;
        }

        @Override
        public Instant now() {
            return Instant.ofEpochSecond(seconds);
        }
    }

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableClock mutableClock() {
            return new MutableClock();
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private MutableClock clock;

    @Test
    void expiredRefreshTokenIsRejectedWithDistinctReason() throws Exception {
        MvcResult tokenResult = mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"alice","password":"alice-pass-123"}"""))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = JsonCodec.mapper().readTree(tokenResult.getResponse().getContentAsByteArray());
        String refresh = body.get("refresh_token").asText();

        clock.advance(121);

        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"refresh_token","client_id":"client-web",
                                 "client_secret":"web-secret","refresh_token":"%s"}""".formatted(refresh)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant_expired"));
    }
}
