package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 端到端验证：令牌生命周期、刷新轮换/重放/撤销、角色/作用域/归属控制、限流。
 * 全程仅使用本地内存与本地状态文件，不依赖任何外部服务或真实凭据。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EndToEndWebTest {

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    ObjectMapper objectMapper;

    @BeforeAll
    static void cleanState() throws Exception {
        Files.deleteIfExists(Path.of("target/test-data/token-state.json"));
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private MultiValueMap<String, String> form(String... kv) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.add(kv[i], kv[i + 1]);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private JsonNode postForm(String path, String... kv) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<String> resp = rest.postForEntity(url(path),
                new HttpEntity<>(form(kv), headers), String.class);
        try {
            return objectMapper.readTree(resp.getBody());
        } catch (Exception e) {
            throw new IllegalStateException("无法解析响应: " + resp.getBody(), e);
        }
    }

    private ResponseEntity<String> getWith(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(url(path), HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    private JsonNode passwordGrant(String username, String client, String secret, String scope) {
        return postForm("/oauth/token",
                "grant_type", "password",
                "client_id", client,
                "client_secret", secret,
                "username", username,
                "password", "pw",
                "scope", scope);
    }

    // ---------- 令牌端点的基础认证与错误区分 ----------

    @Test
    void missingAndMalformedAuthorizationAreDistinct() {
        ResponseEntity<String> none = getWith("/api/profile", null);
        assertEquals(HttpStatus.UNAUTHORIZED, none.getStatusCode());
        assertEquals("MISSING_AUTHORIZATION", reason(none));

        ResponseEntity<String> malformed = rest.exchange(url("/api/profile"), HttpMethod.GET,
                new HttpEntity<>(new HttpHeaders() {{
                    set("Authorization", "notabearer");
                }}), String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, malformed.getStatusCode());
        assertEquals("MALFORMED", reason(malformed));
    }

    @Test
    void badClientAndBadUserCredentialsAreDistinguishable() {
        JsonNode badClient = postForm("/oauth/token",
                "grant_type", "password", "client_id", "full", "client_secret", "wrong",
                "username", "admin", "password", "pw");
        assertEquals("invalid_client", badClient.get("error").asText());

        JsonNode badUser = postForm("/oauth/token",
                "grant_type", "password", "client_id", "full", "client_secret", "s",
                "username", "admin", "password", "wrong");
        assertEquals("invalid_grant", badUser.get("error").asText());

        JsonNode unknownGrant = postForm("/oauth/token",
                "grant_type", "weird", "client_id", "full", "client_secret", "s");
        assertEquals("unsupported_grant_type", unknownGrant.get("error").asText());
    }

    // ---------- 访问令牌：篡改与过期 ----------

    @Test
    void tamperedAndExpiredTokensAreRejectedWithDistinctReasons() throws Exception {
        JsonNode tokens = passwordGrant("admin", "full", "s", "profile:read");
        String access = tokens.get("access_token").asText();

        // 合法访问
        assertEquals(HttpStatus.OK, getWith("/api/profile", access).getStatusCode());

        // 篡改签名（翻转签名首字符）
        int dot = access.lastIndexOf('.');
        char ch = access.charAt(dot + 1);
        char flipped = ch == 'a' ? 'b' : 'a';
        String tampered = access.substring(0, dot + 1) + flipped + access.substring(dot + 2);
        ResponseEntity<String> tamperedResp = getWith("/api/profile", tampered);
        assertEquals(HttpStatus.UNAUTHORIZED, tamperedResp.getStatusCode());
        assertEquals("SIGNATURE_INVALID", reason(tamperedResp));

        // 过期（测试配置 TTL=2s）
        Thread.sleep(2600);
        ResponseEntity<String> expired = getWith("/api/profile", access);
        assertEquals(HttpStatus.UNAUTHORIZED, expired.getStatusCode());
        assertEquals("EXPIRED", reason(expired));
    }

    // ---------- 刷新：轮换、重放、撤销后重放、旧访问令牌失效 ----------

    @Test
    void refreshRotationReplayAndRevokeLifecycle() {
        JsonNode first = passwordGrant("admin", "full", "s", "profile:read doc:read");
        String access1 = first.get("access_token").asText();
        String refresh1 = first.get("refresh_token").asText();

        // 首次轮换成功
        JsonNode rotated = postForm("/oauth/token",
                "grant_type", "refresh_token", "client_id", "full", "client_secret", "s",
                "refresh_token", refresh1);
        assertEquals("Bearer", rotated.get("token_type").asText());
        String refresh2 = rotated.get("refresh_token").asText();
        assertNotNull(refresh2);

        // 轮换后的新访问令牌必须仍携带原授权作用域
        ResponseEntity<String> rotatedScoped = getWith("/api/documents/doc-admin",
                rotated.get("access_token").asText());
        assertEquals(HttpStatus.OK, rotatedScoped.getStatusCode(),
                "刷新后的令牌应保留 doc:read 与资源访问能力");

        // 旧访问令牌在轮换后立即失效
        ResponseEntity<String> denied = getWith("/api/profile", access1);
        assertEquals(HttpStatus.UNAUTHORIZED, denied.getStatusCode());
        assertEquals("TOKEN_DENIED", reason(denied));

        // 超过宽限窗口后重放旧刷新令牌 -> REPLAYED（且家族被撤销）
        pauseBeyondGrace();
        JsonNode replay = postForm("/oauth/token",
                "grant_type", "refresh_token", "client_id", "full", "client_secret", "s",
                "refresh_token", refresh1);
        assertEquals("REPLAYED", replay.get("reason").asText());

        // 家族因重放被撤销，新刷新令牌也不能再用
        JsonNode afterReplay = postForm("/oauth/token",
                "grant_type", "refresh_token", "client_id", "full", "client_secret", "s",
                "refresh_token", refresh2);
        assertEquals("REVOKED", afterReplay.get("reason").asText());

        // 另起一个家族：主动撤销后重放得到 REVOKED
        JsonNode other = passwordGrant("admin", "full", "s", "profile:read");
        String otherRefresh = other.get("refresh_token").asText();
        JsonNode revokeOk = postForm("/oauth/revoke",
                "client_id", "full", "client_secret", "s", "token", otherRefresh);
        assertTrue(revokeOk.get("revoked").asBoolean());
        JsonNode revokedReplay = postForm("/oauth/token",
                "grant_type", "refresh_token", "client_id", "full", "client_secret", "s",
                "refresh_token", otherRefresh);
        assertEquals("REVOKED", revokedReplay.get("reason").asText());

        // 撤销后当前访问令牌立即失效
        ResponseEntity<String> accessAfterRevoke = getWith("/api/profile",
                other.get("access_token").asText());
        assertEquals("TOKEN_DENIED", reason(accessAfterRevoke));
    }

    @Test
    void refreshTokenClientMismatchIsDistinguishable() {
        JsonNode tokens = passwordGrant("admin", "full", "s", "profile:read");
        JsonNode mismatch = postForm("/oauth/token",
                "grant_type", "refresh_token", "client_id", "limited", "client_secret", "s2",
                "refresh_token", tokens.get("refresh_token").asText());
        assertEquals("CLIENT_MISMATCH", mismatch.get("reason").asText());
    }

    @Test
    void concurrentRefreshRotationSucceedsExactlyOnce() throws Exception {
        JsonNode tokens = passwordGrant("user", "full", "s", "profile:read");
        String refresh = tokens.get("refresh_token").asText();

        int n = 20;
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch ready = new CountDownLatch(n);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        Map<String, AtomicInteger> reasons = new java.util.concurrent.ConcurrentHashMap<>();

        try {
            for (int i = 0; i < n; i++) {
                Future<?> f = pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    JsonNode r = postForm("/oauth/token",
                            "grant_type", "refresh_token", "client_id", "full", "client_secret", "s",
                            "refresh_token", refresh);
                    if (r.has("access_token")) {
                        ok.incrementAndGet();
                    } else {
                        reasons.computeIfAbsent(r.get("reason").asText(),
                                k -> new AtomicInteger()).incrementAndGet();
                    }
                    return null;
                });
            }
            assertTrue(ready.await(15, TimeUnit.SECONDS));
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }

        assertEquals(1, ok.get(), "并发刷新最多一次成功");
        int rejected = reasons.values().stream().mapToInt(AtomicInteger::get).sum();
        assertEquals(n - 1, rejected, "其余必须全部被拒绝");
        // 允许 CONCURRENT_REUSE 与 REPLAYED（取决于调度），但不得有成功之外的其它结果
        assertTrue(reasons.containsKey("CONCURRENT_REUSE") || reasons.containsKey("REPLAYED"),
                "拒绝原因必须可区分: " + reasons);
    }

    // ---------- 访问控制：角色 / 作用域 / 资源归属 ----------

    @Test
    void roleScopeAndOwnershipRejectionsAreDistinguishable() {
        // user + limited（无 admin:read 作用域）
        JsonNode limitedUser = passwordGrant("user", "limited", "s2", "profile:read doc:read");
        String luToken = limitedUser.get("access_token").asText();

        // 角色不足：user 访问 admin
        ResponseEntity<String> missingRole = getWith("/api/admin", luToken);
        assertEquals(HttpStatus.FORBIDDEN, missingRole.getStatusCode());
        assertEquals("MISSING_ROLE", reason(missingRole));

        // 作用域不足：admin + limited 有 ADMIN 角色但没有 admin:read
        JsonNode limitedAdmin = passwordGrant("admin", "limited", "s2", "profile:read doc:read");
        ResponseEntity<String> insufficientScope = getWith("/api/admin",
                limitedAdmin.get("access_token").asText());
        assertEquals(HttpStatus.FORBIDDEN, insufficientScope.getStatusCode());
        assertEquals("INSUFFICIENT_SCOPE", reason(insufficientScope));

        // 资源归属不符
        ResponseEntity<String> ownerMismatch = getWith("/api/documents/doc-admin", luToken);
        assertEquals(HttpStatus.FORBIDDEN, ownerMismatch.getStatusCode());
        assertEquals("RESOURCE_OWNER_MISMATCH", reason(ownerMismatch));

        // 归属匹配可访问
        ResponseEntity<String> ownerOk = getWith("/api/documents/doc-user", luToken);
        assertEquals(HttpStatus.OK, ownerOk.getStatusCode());

        // 全权限管理员通过
        JsonNode fullAdmin = passwordGrant("admin", "full", "s", "profile:read admin:read doc:read");
        assertEquals(HttpStatus.OK,
                getWith("/api/admin", fullAdmin.get("access_token").asText()).getStatusCode());
    }

    // ---------- 限流 ----------

    @Test
    void rateLimitRejectsExcessRequestsWithDistinctReason() {
        JsonNode tokens = passwordGrant("user", "full", "s", "profile:read");
        String token = tokens.get("access_token").asText();
        // 配额为 3 / 10s（该主体此前可能已有计数，故只断言“出现 429 且原因可区分”）
        boolean sawTooMany = false;
        for (int i = 0; i < 8; i++) {
            ResponseEntity<String> resp = getWith("/api/profile", token);
            if (resp.getStatusCode().value() == 429) {
                assertEquals("TOO_MANY_REQUESTS", reason(resp));
                sawTooMany = true;
                break;
            }
            assertEquals(HttpStatus.OK, resp.getStatusCode());
        }
        assertTrue(sawTooMany, "超出窗口配额必须返回 429");
    }

    private void pauseBeyondGrace() {
        try {
            Thread.sleep(400);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String reason(ResponseEntity<String> resp) {
        try {
            JsonNode node = objectMapper.readTree(resp.getBody());
            return node.path("reason").asText();
        } catch (Exception e) {
            throw new IllegalStateException("响应不是 JSON: " + resp.getBody(), e);
        }
    }
}
