package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 会话可见/定向踢出 + 只读自检的全栈测试。
 * 所有用户测试前先把限流配额调高，避免顺序执行时被限流干扰。
 */
@SpringBootTest(properties = {
        "auth.security.hmacKey=integration-test-hmac-key",
        "auth.token.stateFile=target/test-data/it-sessions.json",
        "auth.token.accessTtlSeconds=3600",
        "auth.token.refreshTtlSeconds=3600",
        "auth.ratelimit.maxRequests=10000",
        "auth.ratelimit.windowSeconds=60"
})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SessionAndIntrospectionIntegrationTest {

    @Autowired
    private MockMvc mvc;

    static {
        // 该类的会话断言依赖全新状态；在 Spring 启动前清掉上一轮残留文件。
        try {
            Files.deleteIfExists(Path.of("target/test-data/it-sessions.json"));
        } catch (Exception ignored) {
            // 首次运行文件不存在属正常
        }
    }

    private String[] login(String clientId, String clientSecret, String username) throws Exception {
        MvcResult result = mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"%s","client_secret":"%s",
                                 "username":"%s","password":"%s-pass-123"}"""
                                .formatted(clientId, clientSecret, username, username)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray());
        return new String[]{json.get("access_token").asText(), json.get("refresh_token").asText()};
    }

    private String adminToken() throws Exception {
        return login("client-web", "web-secret", "admin")[0];
    }

    @Test
    @Order(1)
    void sessionsAreListableAndExcludeTokenRawValues() throws Exception {
        String[] web = login("client-web", "web-secret", "alice");
        login("client-readonly", "readonly-secret", "alice");

        MvcResult listResult = mvc.perform(get("/api/sessions/u-alice")
                        .header("Authorization", "Bearer " + web[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeCount").value(2))
                .andExpect(jsonPath("$.sessions[0].clientId").exists())
                .andExpect(jsonPath("$.sessions[0].createdAt").exists())
                .andExpect(jsonPath("$.sessions[0].lastUsedAt").exists())
                .andReturn();
        String body = listResult.getResponse().getContentAsString();
        // 概览里绝不能出现访问/刷新令牌原文。
        org.assertj.core.api.Assertions.assertThat(body).doesNotContain(web[0]).doesNotContain(web[1]);

        // 其它用户不能看 alice 的会话。
        String[] bob = login("client-web", "web-secret", "bob");
        mvc.perform(get("/api/sessions/u-alice").header("Authorization", "Bearer " + bob[0]))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_subject_mismatch"));
    }

    @Test
    @Order(2)
    void loggingOutOneSessionKillsOnlyItsAccessToken() throws Exception {
        String[] bootstrap = login("client-web", "web-secret", "bob");
        // 清掉测试1留下的 bob 历史会话，得到干净起点（此令牌之后不再使用）。
        mvc.perform(delete("/api/sessions/u-bob").header("Authorization", "Bearer " + bootstrap[0]))
                .andExpect(status().isOk());

        String[] web = login("client-web", "web-secret", "bob");
        String[] readOnly = login("client-readonly", "readonly-secret", "bob");

        // 同秒登录时 createdAt 可能相同，按 clientId 精确选出 client-web 那一个会话。
        JsonNode bobSessions = JsonCodec.mapper().readTree(
                mvc.perform(get("/api/sessions/u-bob").header("Authorization", "Bearer " + web[0]))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.activeCount").value(2))
                        .andReturn().getResponse().getContentAsByteArray())
                .get("sessions");
        String sessionWeb = null;
        for (JsonNode s : bobSessions) {
            if ("client-web".equals(s.get("clientId").asText())) {
                sessionWeb = s.get("sessionId").asText();
            }
        }
        org.assertj.core.api.Assertions.assertThat(sessionWeb).isNotBlank();

        mvc.perform(delete("/api/sessions/u-bob/" + sessionWeb)
                        .header("Authorization", "Bearer " + web[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("logged_out"));

        // 被注销会话的访问令牌立刻失效。
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + web[0]))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_session_logged_out"));
        // 另一个会话不受影响。
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + readOnly[0]))
                .andExpect(status().isOk());

        // 重复注销同一已结束会话：404 session_not_found。
        mvc.perform(delete("/api/sessions/u-bob/" + sessionWeb)
                        .header("Authorization", "Bearer " + readOnly[0]))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("session_not_found"));
    }

    @Test
    @Order(3)
    void logoutAllAndAdminCanManageOtherUsersSessions() throws Exception {
        String[] alice1 = login("client-web", "web-secret", "alice");
        String[] alice2 = login("client-readonly", "readonly-secret", "alice");
        String admin = adminToken();

        // 管理员可列出并注销 alice 的全部会话（含测试1遗留的，注销前数量不固定，注销后必须为 0）。
        mvc.perform(get("/api/sessions/u-alice").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk());
        mvc.perform(delete("/api/sessions/u-alice").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("logged_out"));

        mvc.perform(get("/api/sessions/u-alice").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeCount").value(0));
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + alice1[0]))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_session_logged_out"));
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + alice2[0]))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_session_logged_out"));
    }

    @Test
    @Order(4)
    void introspectionEndpointCoversValidAndDistinctInvalidReasons() throws Exception {
        String[] alice = login("client-web", "web-secret", "alice");

        // 有效令牌。
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(alice[0])))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.subject").value("u-alice"))
                .andExpect(jsonPath("$.sessionId").exists());

        // 乱填/格式错误：HTTP 200 + active=false，不抛异常。
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"garbage.token.value"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("malformed_token"));
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"not-a-jwt"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("malformed_token"));

        // 结构合法但签名末位被篡改：bad_signature，与 unknown_signing_key 分开。
        String tampered = alice[0].substring(0, alice[0].length() - 1)
                + (alice[0].endsWith("A") ? "B" : "A");
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(tampered)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("bad_signature"));

        // 自检不改变状态：紧接着该令牌仍可访问。
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + alice[0]))
                .andExpect(status().isOk());

        // 会话注销后自检原因：session_logged_out。
        String sessionId = JsonCodec.mapper().readTree(
                mvc.perform(get("/api/sessions/u-alice")
                                .header("Authorization", "Bearer " + alice[0]))
                        .andReturn().getResponse().getContentAsByteArray())
                .findValuesAsText("sessionId").get(0);
        mvc.perform(delete("/api/sessions/u-alice/" + sessionId)
                        .header("Authorization", "Bearer " + alice[0]))
                .andExpect(status().isOk());
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(alice[0])))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("token_session_logged_out"));

        // 客户端凭据错误：仍走 401 invalid_client（自检端点本身受保护）。
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"wrong","token":"x"}"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));

        // 缺少 token 字段：不抛异常，200 + inactive + missing_token。
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("missing_token"));

        // body 不是合法 JSON：由全局处理器收敛为 400 invalid_request（不向调用方抛栈）。
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }
}
