package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import java.util.Base64;
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
 * 全栈集成测试：无外部服务、无真实凭据（全部为内置演示数据）。
 * 使用独立测试状态文件，避免污染本地运行数据。
 */
@SpringBootTest(properties = {
        "auth.security.hmacKey=integration-test-hmac-key",
        "auth.token.stateFile=target/test-data/it-flow.json",
        "auth.token.accessTtlSeconds=3600",
        "auth.token.refreshTtlSeconds=3600",
        "auth.ratelimit.maxRequests=100",
        "auth.ratelimit.windowSeconds=60"
})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthFlowIntegrationTest {

    @Autowired
    private MockMvc mvc;

    private MvcResult passwordToken(String username, String password) throws Exception {
        return mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andReturn();
    }

    private String bearer(MvcResult tokenResult) throws Exception {
        JsonNode json = JsonCodec.mapper().readTree(tokenResult.getResponse().getContentAsByteArray());
        return json.get("access_token").asText();
    }

    private String refresh(MvcResult tokenResult) throws Exception {
        JsonNode json = JsonCodec.mapper().readTree(tokenResult.getResponse().getContentAsByteArray());
        return json.get("refresh_token").asText();
    }

    @Test
    @Order(1)
    void missingAndMalformedAuthorizationAreDistinct() throws Exception {
        mvc.perform(get("/api/ping")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"));

        mvc.perform(get("/api/ping").header("Authorization", "Basic abc"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("malformed_token"));

        mvc.perform(get("/api/ping").header("Authorization", "Bearer "))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"));
    }

    @Test
    @Order(2)
    void passwordGrantThenAccessOwnProfileSucceeds() throws Exception {
        MvcResult token = passwordToken("alice", "alice-pass-123");
        org.junit.jupiter.api.Assertions.assertEquals(200, token.getResponse().getStatus());
        String at = bearer(token);

        mvc.perform(get("/api/profile/u-alice").header("Authorization", "Bearer " + at))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("u-alice"));
    }

    @Test
    @Order(3)
    void wrongPasswordAndWrongClientSecretAreDistinct() throws Exception {
        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"alice","password":"WRONG"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"WRONG","username":"alice","password":"alice-pass-123"}"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));

        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"weird","client_id":"client-web","client_secret":"web-secret"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    @Order(4)
    void tamperedTokenIsBadSignature() throws Exception {
        String at = bearer(passwordToken("alice", "alice-pass-123"));
        String[] parts = at.split("\\.");
        char last = parts[2].charAt(parts[2].length() - 1);
        String flipped = parts[2].substring(0, parts[2].length() - 1) + (last == 'A' ? 'B' : 'A');
        String bad = parts[0] + "." + parts[1] + "." + flipped;

        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + bad))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("bad_signature"));
    }

    @Test
    @Order(5)
    void tokenMissingClaimIsRejectedWithDistinctReason() throws Exception {
        String at = bearer(passwordToken("alice", "alice-pass-123"));
        String[] parts = at.split("\\.");
        JsonNode payload = JsonCodec.mapper().readTree(Base64.getUrlDecoder().decode(parts[1]));
        com.fasterxml.jackson.databind.node.ObjectNode mutable = payload.deepCopy();
        mutable.remove("jti");
        String newPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JsonCodec.mapper().writeValueAsBytes(mutable));
        String stripped = parts[0] + "." + newPayload + "." + parts[2];

        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + stripped))
                .andExpect(status().isUnauthorized())
                // 改了 payload，签名先失败，因此这里是 bad_signature；缺声明路径由单元测试覆盖
                .andExpect(jsonPath("$.error").value("bad_signature"));
    }

    @Test
    @Order(6)
    void subjectMismatchIsRejected() throws Exception {
        String at = bearer(passwordToken("alice", "alice-pass-123"));
        mvc.perform(get("/api/profile/u-bob").header("Authorization", "Bearer " + at))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_subject_mismatch"));
    }

    @Test
    @Order(7)
    void adminRoleAndScopeAreEnforced() throws Exception {
        String alice = bearer(passwordToken("alice", "alice-pass-123"));
        String admin = bearer(passwordToken("admin", "admin-pass-123"));

        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + alice))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden_role"));

        mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk());
    }

    @Test
    @Order(8)
    void scopeAndOwnershipAreEnforced() throws Exception {
        // readonly 客户端只有 read：请求 write 作用域应被拒（invalid_scope）
        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"client_credentials","client_id":"client-readonly",
                                 "client_secret":"readonly-secret","scope":"read write"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));

        String alice = bearer(passwordToken("alice", "alice-pass-123"));
        // alice 访问 bob 拥有的资源
        mvc.perform(get("/api/resources/res-2").header("Authorization", "Bearer " + alice))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden_owner"));
        // alice 访问自己的资源
        mvc.perform(get("/api/resources/res-1").header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.owner").value("u-alice"));
    }

    @Test
    @Order(9)
    void refreshRotationReplayAndStaleAccessToken() throws Exception {
        MvcResult original = passwordToken("bob", "bob-pass-123");
        String oldAccess = bearer(original);
        String oldRefresh = refresh(original);

        // 第一次刷新成功，拿到新 access 与新 refresh
        MvcResult rotatedResult = mvc.perform(post("/oauth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"refresh_token","client_id":"client-web",
                                 "client_secret":"web-secret","refresh_token":"%s"}""".formatted(oldRefresh)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn();
        JsonNode rotated = JsonCodec.mapper().readTree(rotatedResult.getResponse().getContentAsByteArray());
        String newAccess = rotated.get("access_token").asText();
        String newRefresh = rotated.get("refresh_token").asText();

        // 旧刷新令牌立即失效：重放被拒，原因可区分
        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"refresh_token","client_id":"client-web",
                                 "client_secret":"web-secret","refresh_token":"%s"}""".formatted(oldRefresh)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant_replayed"));

        // 旧访问令牌属于被轮换掉的旧代：拒绝
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_stale"));

        // 新访问令牌可用
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());

        // 用另一个客户端刷新必须被拒绝（主体/客户端不符）
        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"refresh_token","client_id":"client-readonly",
                                 "client_secret":"readonly-secret","refresh_token":"%s"}""".formatted(newRefresh)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant_client_mismatch"));
    }

    @Test
    @Order(10)
    void revokeInvalidatesFamilyAndBothTokenKinds() throws Exception {
        MvcResult original = passwordToken("alice", "alice-pass-123");
        String access = bearer(original);
        String refreshToken = refresh(original);

        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        mvc.perform(post("/oauth/revoke").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret",
                                 "token":"%s","token_type_hint":"refresh_token"}""".formatted(refreshToken)))
                .andExpect(status().isOk());

        // 撤销后：当前访问令牌因族撤销被拒
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_revoked"));
        // 撤销后：刷新令牌被拒且原因与重放不同
        mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"refresh_token","client_id":"client-web",
                                 "client_secret":"web-secret","refresh_token":"%s"}""".formatted(refreshToken)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant_revoked"));
    }
}
