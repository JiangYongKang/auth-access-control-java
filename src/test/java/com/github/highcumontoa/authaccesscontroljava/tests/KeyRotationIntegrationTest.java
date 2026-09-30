package com.github.highcumontoa.authaccesscontroljava.tests;

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
 * 密钥平滑轮换端到端验证：像 PersistenceRestartTest 一样手动启停两个真实 Spring 上下文，
 * 它们共享同一会话状态文件，但载入不同的签名密钥配置。
 *
 * <pre>
 * 上下文1：active=k-old，一把旧密钥签发令牌
 * 上下文2：active=k-new，同时保留 k-old —— 旧令牌仍可验；新登录的令牌走 k-new
 * 上下文3：只保留 k-new（摘掉 k-old）—— 旧令牌立刻 unknown_signing_key，新令牌继续有效
 * </pre>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyRotationIntegrationTest {

    private static final Path STATE_FILE = Path.of("target/test-data/it-key-rotation.json");
    private static String oldToken;
    private static String newToken;

    private MockMvc mockMvc(ConfigurableApplicationContext ctx) {
        Filter[] filters = ctx.getBeansOfType(Filter.class).values().toArray(new Filter[0]);
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx)
                .addFilters(filters)
                .build();
    }

    private ConfigurableApplicationContext start(String... keys) {
        String[] base = {
                "--auth.token.stateFile=" + STATE_FILE,
                "--auth.token.accessTtlSeconds=3600",
                "--auth.token.refreshTtlSeconds=3600",
                "--auth.ratelimit.maxRequests=1000",
                "--server.port=0"};
        String[] all = new String[base.length + keys.length];
        System.arraycopy(base, 0, all, 0, base.length);
        System.arraycopy(keys, 0, all, base.length, keys.length);
        return new SpringApplicationBuilder(
                com.github.highcumontoa.authaccesscontroljava.Application.class).run(all);
    }

    private String loginAlice(MockMvc mvc) throws Exception {
        var result = mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"alice","password":"alice-pass-123"}"""))
                .andExpect(status().isOk())
                .andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray())
                .get("access_token").asText();
    }

    @Test
    @Order(1)
    void issueWithOldKey() throws Exception {
        Files.deleteIfExists(STATE_FILE);
        Files.createDirectories(STATE_FILE.toAbsolutePath().getParent());
        ConfigurableApplicationContext ctx = start(
                "--auth.security.signing-keys.k-old=old-secret-0123456789",
                "--auth.security.active-key-id=k-old");
        try {
            oldToken = loginAlice(mockMvc(ctx));
            mockMvc(ctx).perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(2)
    void newKeyActiveButOldKeyStillAccepted() throws Exception {
        ConfigurableApplicationContext ctx = start(
                "--auth.security.signing-keys.k-old=old-secret-0123456789",
                "--auth.security.signing-keys.k-new=new-secret-0123456789",
                "--auth.security.active-key-id=k-new");
        try {
            MockMvc mvc = mockMvc(ctx);
            // 线上尚未到期的旧令牌继续可用（平滑轮换，不掉线）。
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isOk());
            // 新签发的令牌走 k-new。
            newToken = loginAlice(mvc);
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + newToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(3)
    void removingOldKeyKillsOldTokensImmediatelyWhileNewTokensSurvive() throws Exception {
        ConfigurableApplicationContext ctx = start(
                "--auth.security.signing-keys.k-new=new-secret-0123456789",
                "--auth.security.active-key-id=k-new");
        try {
            MockMvc mvc = mockMvc(ctx);
            // 旧密钥一摘除：由它签出的旧令牌立刻失效，且原因是"不认识的密钥"，不是签名对不上。
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + oldToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("unknown_signing_key"));
            // 当前密钥签的令牌继续可用。
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + newToken))
                    .andExpect(status().isOk());
        } finally {
            ctx.close();
            Files.deleteIfExists(STATE_FILE);
        }
    }
}
