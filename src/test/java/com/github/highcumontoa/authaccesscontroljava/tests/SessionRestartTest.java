package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.Application;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
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
 * 会话重启一致性：进程重启后，已建立的会话仍能列出、已注销会话保持注销（不退化为「未知」），
 * 被注销会话此前发出的访问令牌依旧被拒。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SessionRestartTest {

    private static final Path STATE_FILE = Path.of("target/test-data/it-session-restart.json");
    private static String adminToken;
    private static String revokedAccessToken;
    private static String keptAccessToken;
    private static String revokedSessionId;
    private static String keptSessionId;

    private MockMvc mockMvc(ConfigurableApplicationContext ctx) {
        jakarta.servlet.Filter[] filters = ctx.getBeansOfType(jakarta.servlet.Filter.class)
                .values().toArray(new jakarta.servlet.Filter[0]);
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx)
                .addFilters(filters).build();
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
        return new SpringApplicationBuilder(Application.class).run(args());
    }

    private String login(MockMvc mvc, String user, String pass) throws Exception {
        var result = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"%s","password":"%s"}"""
                                .formatted(user, pass)))
                .andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray())
                .get("access_token").asText();
    }

    private JsonNode sessions(MockMvc mvc) throws Exception {
        var result = mvc.perform(get("/api/admin/sessions/u-alice")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk()).andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray());
    }

    private static String famOf(String token) throws Exception {
        return JsonCodec.mapper()
                .readTree(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[1]))
                .get("fam").asText();
    }

    @Test
    @Order(1)
    void firstRunCreatesTwoSessionsAndRevokesOne() throws Exception {
        Files.deleteIfExists(STATE_FILE);
        Files.createDirectories(STATE_FILE.toAbsolutePath().getParent());
        ConfigurableApplicationContext ctx = start();
        try {
            MockMvc mvc = mockMvc(ctx);
            adminToken = login(mvc, "admin", "admin-pass-123");
            revokedAccessToken = login(mvc, "alice", "alice-pass-123");
            keptAccessToken = login(mvc, "alice", "alice-pass-123");
            revokedSessionId = famOf(revokedAccessToken);
            keptSessionId = famOf(keptAccessToken);

            mvc.perform(post("/api/admin/sessions/u-alice/" + revokedSessionId)
                            .header("Authorization", "Bearer " + adminToken))
                    .andExpect(status().isOk());

            // 注销即时生效
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + revokedAccessToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("token_family_revoked"));
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + keptAccessToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(2)
    void secondRunKeepsSessionsAndRevokedStateConsistent() throws Exception {
        ConfigurableApplicationContext ctx = start();
        try {
            MockMvc mvc = mockMvc(ctx);

            // 已注销会话的旧访问令牌重启后依旧被拒（不退回「未知/stale」）
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + revokedAccessToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("token_family_revoked"));
            // 未注销会话的访问令牌重启后继续有效
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + keptAccessToken))
                    .andExpect(status().isOk());

            // 重新登录管理员以列出会话；只剩那个未注销的会话
            adminToken = login(mvc, "admin", "admin-pass-123");
            JsonNode list = sessions(mvc);
            org.junit.jupiter.api.Assertions.assertEquals(1, list.get("count").asInt());
            String remainingId = list.get("sessions").get(0).get("sessionId").asText();
            org.junit.jupiter.api.Assertions.assertEquals(keptSessionId, remainingId);
            org.junit.jupiter.api.Assertions.assertNotEquals(revokedSessionId, remainingId);

            // 对已注销会话再次定向注销 -> session_not_found（状态被持久化，不是「没发生过」）
            mvc.perform(post("/api/admin/sessions/u-alice/" + revokedSessionId)
                            .header("Authorization", "Bearer " + adminToken))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.error").value("session_not_found"));
        } finally {
            ctx.close();
            Files.deleteIfExists(STATE_FILE);
        }
    }
}
