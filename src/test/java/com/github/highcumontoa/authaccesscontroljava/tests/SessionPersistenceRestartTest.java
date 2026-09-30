package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import jakarta.servlet.Filter;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * 会话注销/批量注销状态在进程重启后必须保持一致：
 * 已注销会话既不会退化为"未知"，也不会在重启后又恢复可用；同主体的其它会话继续有效。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SessionPersistenceRestartTest {

    private static final Path STATE_FILE = Path.of("target/test-data/it-session-restart.json");
    private static String loggedOutToken;
    private static String survivingToken;
    private static String loggedOutSessionId;

    private MockMvc mockMvc(ConfigurableApplicationContext ctx) {
        Filter[] filters = ctx.getBeansOfType(Filter.class).values().toArray(new Filter[0]);
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx)
                .addFilters(filters)
                .build();
    }

    private String[] args() {
        return new String[]{
                "--auth.security.hmacKey=session-restart-hmac-key",
                "--auth.token.stateFile=" + STATE_FILE,
                "--auth.token.accessTtlSeconds=3600",
                "--auth.token.refreshTtlSeconds=3600",
                "--auth.ratelimit.maxRequests=1000",
                "--server.port=0"};
    }

    private ConfigurableApplicationContext start() {
        return new SpringApplicationBuilder(
                com.github.highcumontoa.authaccesscontroljava.Application.class).run(args());
    }

    private String login(MockMvc mvc, String clientId, String clientSecret) throws Exception {
        var result = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"%s","client_secret":"%s",
                                 "username":"alice","password":"alice-pass-123"}"""
                                .formatted(clientId, clientSecret)))
                .andExpect(status().isOk()).andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray())
                .get("access_token").asText();
    }

    @Test
    @Order(1)
    void firstRunLogsOutOneSessionThenStops() throws Exception {
        Files.deleteIfExists(STATE_FILE);
        Files.createDirectories(STATE_FILE.toAbsolutePath().getParent());
        ConfigurableApplicationContext ctx = start();
        try {
            MockMvc mvc = mockMvc(ctx);
            loggedOutToken = login(mvc, "client-web", "web-secret");
            survivingToken = login(mvc, "client-readonly", "readonly-secret");

            JsonNode sessions = JsonCodec.mapper().readTree(
                    mvc.perform(get("/api/sessions/u-alice")
                                    .header("Authorization", "Bearer " + loggedOutToken))
                            .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray())
                    .get("sessions");
            for (JsonNode s : sessions) {
                if ("client-web".equals(s.get("clientId").asText())) {
                    loggedOutSessionId = s.get("sessionId").asText();
                }
            }
            org.assertj.core.api.Assertions.assertThat(loggedOutSessionId).isNotBlank();

            mvc.perform(delete("/api/sessions/u-alice/" + loggedOutSessionId)
                            .header("Authorization", "Bearer " + loggedOutToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(2)
    void secondRunKeepsLoggedOutSessionOutAndSurvivingSessionAlive() throws Exception {
        ConfigurableApplicationContext ctx = start();
        try {
            MockMvc mvc = mockMvc(ctx);

            // 被注销会话：重启后依旧是"会话被注销"，而不是退化为 stale/unknown。
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + loggedOutToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("token_session_logged_out"));

            // 自检结论同样保持。
            mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                    .formatted(loggedOutToken)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.active").value(false))
                    .andExpect(jsonPath("$.reason").value("token_session_logged_out"));

            // 同主体的另一个会话不受影响，重启后仍有效。
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + survivingToken))
                    .andExpect(status().isOk());
            mvc.perform(get("/api/sessions/u-alice")
                            .header("Authorization", "Bearer " + survivingToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.activeCount").value(1))
                    .andExpect(jsonPath("$.sessions[0].clientId").value("client-readonly"));
        } finally {
            ctx.close();
            Files.deleteIfExists(STATE_FILE);
        }
    }
}
