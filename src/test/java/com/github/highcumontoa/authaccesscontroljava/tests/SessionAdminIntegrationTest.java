package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 端到端：会话可见性与定向踢除 + 只读自检入口。
 */
@SpringBootTest(properties = {
        "auth.security.hmacKey=session-admin-it-hmac-key",
        // 每次运行使用独立状态文件，避免历史会话数据干扰计数
        "auth.token.stateFile=target/test-data/it-sessions-${random.uuid}.json",
        "auth.token.accessTtlSeconds=3600",
        "auth.token.refreshTtlSeconds=3600",
        "auth.ratelimit.maxRequests=1000",
        "auth.ratelimit.windowSeconds=60"
})
@AutoConfigureMockMvc
class SessionAdminIntegrationTest {

    @Autowired
    private MockMvc mvc;

    private String login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"grant_type":"password","client_id":"client-web",
                                 "client_secret":"web-secret","username":"%s","password":"%s"}"""
                                .formatted(username, password)))
                .andExpect(status().isOk()).andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray())
                .get("access_token").asText();
    }

    private JsonNode listSessions(String adminToken, String userId) throws Exception {
        MvcResult result = mvc.perform(get("/api/admin/sessions/" + userId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk()).andReturn();
        return JsonCodec.mapper().readTree(result.getResponse().getContentAsByteArray());
    }

    @Test
    void listRevokeSingleAndAllSessionsInvalidatesAccessTokensImmediately() throws Exception {
        String admin = login("admin", "admin-pass-123");
        // alice 在两个客户端（这里用不同登录代表不同会话/族）分别登录
        String a1 = login("alice", "alice-pass-123");
        String a2 = login("alice", "alice-pass-123");

        // 两个会话都有效，概览含客户端/时间且不含令牌原文
        JsonNode sessions = listSessions(admin, "u-alice");
        org.junit.jupiter.api.Assertions.assertEquals(2, sessions.get("count").asInt());
        String body = sessions.toString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains(a1));
        org.junit.jupiter.api.Assertions.assertFalse(body.contains(a2));
        org.junit.jupiter.api.Assertions.assertTrue(body.contains("sessionId"));
        org.junit.jupiter.api.Assertions.assertTrue(body.contains("lastUsedAt"));

        String sessionId1 = sessions.get("sessions").get(0).get("sessionId").asText();
        String sessionId2 = sessions.get("sessions").get(1).get("sessionId").asText();

        // 从令牌载荷解析各自所属族，避免依赖列表顺序假设
        String fam1 = famOf(a1);
        String fam2 = famOf(a2);
        org.junit.jupiter.api.Assertions.assertTrue(fam1.equals(sessionId1) || fam1.equals(sessionId2));
        // 定向注销 a1 所属的那个会话
        String revokeTarget = fam1;

        // 非管理员看不到会话列表
        mvc.perform(get("/api/admin/sessions/u-alice").header("Authorization", "Bearer " + a1))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden_role"));

        // 定向注销第一个会话：它的访问令牌立即失效，第二个不受影响
        mvc.perform(post("/api/admin/sessions/u-alice/" + revokeTarget)
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));

        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + a1))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_revoked"));
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk());

        // 注销不存在/已注销的会话 -> session_not_found
        mvc.perform(post("/api/admin/sessions/u-alice/" + revokeTarget)
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("session_not_found"));

        // 一次性注销该用户全部剩余会话
        mvc.perform(post("/api/admin/sessions/u-alice").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(1));
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + a2))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_revoked"));
        // 再列：已无有效会话；两个会话都已注销
        JsonNode after = listSessions(admin, "u-alice");
        org.junit.jupiter.api.Assertions.assertEquals(0, after.get("count").asInt());
    }

    private static String famOf(String accessToken) throws Exception {
        String payload = accessToken.split("\\.")[1];
        JsonNode node = JsonCodec.mapper()
                .readTree(java.util.Base64.getUrlDecoder().decode(payload));
        return node.get("fam").asText();
    }

    @Test
    void introspectDistinguishesActiveExpiredRevokedAndMalformed() throws Exception {
        String token = login("bob", "bob-pass-123");

        // 有效
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value("u-bob"));

        // 乱填令牌：200 + active=false + malformed，不抛 5xx
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"garbage###"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("malformed"));

        // 篡改签名：bad_signature
        String[] parts = token.split("\\.");
        char last = parts[2].charAt(parts[2].length() - 1);
        String flipped = parts[2].substring(0, parts[2].length() - 1) + (last == 'A' ? 'B' : 'A');
        String bad = parts[0] + "." + parts[1] + "." + flipped;
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(bad)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("bad_signature"));

        // 显式撤销后自检：token_revoked（与会话注销明确区分）；且不回显令牌原文
        MvcResult revoked = mvc.perform(post("/oauth/revoke").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(token)))
                .andExpect(status().isOk()).andReturn();
        org.junit.jupiter.api.Assertions.assertFalse(
                revoked.getResponse().getContentAsString().contains(token));

        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("token_revoked"));

        // 客户端密钥错误：401，不允许匿名自检
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"WRONG","token":"%s"}"""
                                .formatted(token)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void introspectDistinguishesSessionLogoutFromTokenRevocation() throws Exception {
        String at = login("bob", "bob-pass-123");
        String fam = famOf(at);

        // 自检原本有效
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(at)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true));

        // 会话被管理员踢下线：访问令牌立即失效，自检原因是 session_revoked 而非 token_revoked
        String admin = login("admin", "admin-pass-123");
        mvc.perform(post("/api/admin/sessions/u-bob/" + fam)
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));

        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + at))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_revoked"));

        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"%s"}"""
                                .formatted(at)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("session_revoked"));
    }

    @Test
    void introspectWithoutTokenReturns200InactiveNeverClientError() throws Exception {
        // 字段缺失：200 active=false reason=missing_token（不是 4xx 参数错误）
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("missing_token"));

        // token 为空串 / 纯空白：同样 200
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":""}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("missing_token"));
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"   "}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("missing_token"));

        // 整个 body 为空 / 不是合法 JSON：网关按 200 解析，也不能变成 4xx 或 5xx
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("missing_token"));
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("missing_token"));

        // 乱填/畸形令牌同样 200 + inactive，不报错（客户端凭据仍需正确）
        mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret","token":"garbage###"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.reason").value("malformed"));

        // 响应中不含任何密钥信息
        MvcResult result = mvc.perform(post("/oauth/introspect").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"client_id":"client-web","client_secret":"web-secret"}"""))
                .andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("web-secret"));
    }

    @Test
    void concurrentDuplicateSessionLogoutOverHttpSucceedsExactlyOnce() throws Exception {
        // 两次登录：目标会话将被并发重复注销，另一个会话必须始终不受影响
        String target = login("alice", "alice-pass-123");
        String untouched = login("alice", "alice-pass-123");
        String fam = famOf(target);
        String otherFam = famOf(untouched);
        String admin = login("admin", "admin-pass-123");

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger notFound = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    int code = mvc.perform(post("/api/admin/sessions/u-alice/" + fam)
                                    .header("Authorization", "Bearer " + admin))
                            .andReturn().getResponse().getStatus();
                    if (code == 200) {
                        ok.incrementAndGet();
                    } else if (code == 404) {
                        notFound.incrementAndGet();
                    } else {
                        other.incrementAndGet();
                    }
                } catch (Exception e) {
                    other.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        org.junit.jupiter.api.Assertions.assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));

        // HTTP 语义同样保证：恰好一个 200，其余全部 404 session_not_found
        org.junit.jupiter.api.Assertions.assertEquals(1, ok.get(), "exactly one logout must succeed");
        org.junit.jupiter.api.Assertions.assertEquals(threads - 1, notFound.get());
        org.junit.jupiter.api.Assertions.assertEquals(0, other.get());

        // 目标会话已发的访问令牌立即失效；同主体另一个会话的令牌照常可用
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + target))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_family_revoked"));
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + untouched))
                .andExpect(status().isOk());

        // 再列会话：只剩未受牵连的那一个
        JsonNode sessions = listSessions(admin, "u-alice");
        org.junit.jupiter.api.Assertions.assertEquals(1, sessions.get("count").asInt());
        org.junit.jupiter.api.Assertions.assertEquals(otherFam,
                sessions.get("sessions").get(0).get("sessionId").asText());
    }
}
