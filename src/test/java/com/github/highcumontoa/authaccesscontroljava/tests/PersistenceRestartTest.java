package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
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
 * 不使用 @SpringBootTest 的共享上下文，而是手动创建/关闭两个完整的 Spring 上下文，
 * 它们读写同一个本地状态文件，从而真实模拟"进程重启后撤销状态仍保持一致"。
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PersistenceRestartTest {

    private static final Path STATE_FILE = Path.of("target/test-data/it-restart.json");
    private static String accessToken;
    private static String refreshToken;

    private MockMvc mockMvc(ConfigurableApplicationContext ctx) {
        // 手动构建上下文时需要显式注册 Servlet Filter（AuthFilter），否则过滤器链不会生效。
        jakarta.servlet.Filter[] filters = ctx.getBeansOfType(jakarta.servlet.Filter.class)
                .values().toArray(new jakarta.servlet.Filter[0]);
        return MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx)
                .addFilters(filters)
                .build();
    }

    private String[] overrideArgs() {
        return new String[]{
                "--auth.security.hmacKey=restart-test-hmac-key",
                "--auth.token.stateFile=" + STATE_FILE,
                "--auth.token.accessTtlSeconds=3600",
                "--auth.token.refreshTtlSeconds=3600",
                "--server.port=0"};
    }

    private ConfigurableApplicationContext startContext() {
        return new SpringApplicationBuilder(
                com.github.highcumontoa.authaccesscontroljava.Application.class)
                .run(overrideArgs());
    }

    @Test
    @Order(1)
    void firstRunIssuesAndRevokesFamilyThenShutsDown() throws Exception {
        Files.deleteIfExists(STATE_FILE);
        Files.createDirectories(STATE_FILE.toAbsolutePath().getParent());
        ConfigurableApplicationContext ctx = startContext();
        try {
            MockMvc mvc = mockMvc(ctx);

            var tokenResult = mvc.perform(post("/oauth/token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"grant_type":"password","client_id":"client-web",
                                     "client_secret":"web-secret","username":"alice",
                                     "password":"alice-pass-123"}"""))
                    .andReturn();
            JsonNode body = JsonCodec.mapper().readTree(tokenResult.getResponse().getContentAsByteArray());
            accessToken = body.get("access_token").asText();
            refreshToken = body.get("refresh_token").asText();

            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + accessToken))
                    .andExpect(status().isOk());

            mvc.perform(post("/oauth/revoke").contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"client_id":"client-web","client_secret":"web-secret",
                                     "token":"%s","token_type_hint":"refresh_token"}""".formatted(refreshToken)))
                    .andExpect(status().isOk());

            String json = Files.readString(STATE_FILE);
            assertThat(json).contains("\"revoked\" : true");
            assertThat(json).doesNotContain(refreshToken);
        } finally {
            ctx.close();
        }
    }

    @Test
    @Order(2)
    void secondRunLoadsStateAndStillRejectsRevokedFamily() throws Exception {
        // 关键：不删除状态文件，直接启动第二个"进程"
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder(
                com.github.highcumontoa.authaccesscontroljava.Application.class)
                .run(overrideArgs());
        try {
            MockMvc mvc = mockMvc(ctx);

            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + accessToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("token_family_revoked"));

            mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"grant_type":"refresh_token","client_id":"client-web",
                                     "client_secret":"web-secret","refresh_token":"%s"}""".formatted(refreshToken)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_grant_revoked"));
        } finally {
            ctx.close();
            Files.deleteIfExists(STATE_FILE);
        }
    }
}
