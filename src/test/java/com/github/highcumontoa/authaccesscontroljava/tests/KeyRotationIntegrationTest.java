package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.Application;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * 端到端：多密钥平滑轮换。
 * 用不同的 --auth.security.keys / active-key-id 启动多个完整上下文（同一状态文件）：
 * 阶段一 active=k1 登录拿令牌；阶段二切到 k2 但保留 k1（旧令牌仍可用）；
 * 阶段三摘掉 k1（旧令牌立即 unknown_signing_key，k2 新令牌正常）。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyRotationIntegrationTest {

    private static final java.nio.file.Path STATE_FILE =
            java.nio.file.Path.of("target/test-data/it-keyrotation.json");
    private static String oldToken;
    private static String newToken;

    private MockMvc mockMvc(ConfigurableApplicationContext ctx) {
        jakarta.servlet.Filter[] filters = ctx.getBeansOfType(jakarta.servlet.Filter.class)
                .values().toArray(new jakarta.servlet.Filter[0]);
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx)
                .addFilters(filters).build();
    }

    @SafeVarargs
    private ConfigurableApplicationContext start(String active, Map<String, String>... keySets) {
        List<String> args = new ArrayList<>(List.of(
                "--auth.token.stateFile=" + STATE_FILE,
                // 多密钥模式与旧单密钥互斥：显式清空默认 hmac-key
                "--auth.security.hmacKey=",
                "--auth.token.accessTtlSeconds=3600",
                "--auth.token.refreshTtlSeconds=3600",
                "--auth.security.activeKeyId=" + active,
                "--server.port=0"));
        for (Map<String, String> set : keySets) {
            for (Map.Entry<String, String> e : set.entrySet()) {
                args.add("--auth.security.keys." + e.getKey() + "=" + e.getValue());
            }
        }
        return new SpringApplicationBuilder(Application.class).run(args.toArray(String[]::new));
    }

    private String login(MockMvc mvc) throws Exception {
        MvcResult result = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"alice",
                                 "password":"alice-pass-123"}"""))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray());
        return body.get("access_token").asText();
    }

    @Test
    @Order(1)
    void phaseOneIssuesWithK1() throws Exception {
        java.nio.file.Files.deleteIfExists(STATE_FILE);
        java.nio.file.Files.createDirectories(STATE_FILE.toAbsolutePath().getParent());
        ConfigurableApplicationContext ctx = start("k1",
                Map.of("k1", "secret-key-one", "k2", "secret-key-two"));
        try {
            oldToken = login(mockMvc(ctx));
            mockMvc(ctx).perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(2)
    void phaseTwoRotatesActiveToK2ButKeepsK1OldTokenStillValid() throws Exception {
        ConfigurableApplicationContext ctx = start("k2",
                Map.of("k1", "secret-key-one", "k2", "secret-key-two"));
        try {
            MockMvc mvc = mockMvc(ctx);
            // 旧密钥仍配置：旧令牌继续通过
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isOk());
            // 新登录走 k2
            newToken = login(mvc);
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + newToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(3)
    void phaseThreeRemovesK1OldTokenImmediatelyUnknownNewTokenFine() throws Exception {
        ConfigurableApplicationContext ctx = start("k2", Map.of("k2", "secret-key-two"));
        try {
            MockMvc mvc = mockMvc(ctx);
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("unknown_signing_key"));
            // k2 签发的令牌继续有效
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + newToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
            java.nio.file.Files.deleteIfExists(STATE_FILE);
        }
    }
}
