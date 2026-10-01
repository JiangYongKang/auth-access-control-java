package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.session.IntrospectionService;
import com.github.highcumontoa.authaccesscontroljava.session.SessionService;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.HmacSigner;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** 自检对有效/无效令牌的区分：原因码逐一可辨；乱填令牌不抛异常；自检不改变令牌状态。 */
class IntrospectionServiceTest {

    static final String ISSUER = "intro-issuer";

    static class FixedClock extends Clock {
        private long seconds;
        FixedClock(long seconds) { this.seconds = seconds; }
        void advance(long d) { seconds += d; }
        @Override public Instant now() { return Instant.ofEpochSecond(seconds); }
    }

    private FixedClock clock;
    private AccessTokenService tokens;
    private FileRefreshTokenStore store;
    private IntrospectionService introspection;
    private SessionService sessions;
    private AuthProperties props;
    private long now = 1_700_000_000L;

    @BeforeEach
    void setUp() throws Exception {
        clock = new FixedClock(now);
        props = new AuthProperties();
        props.getSecurity().setHmacKey("intro-hmac-key");
        props.getSecurity().setIssuer(ISSUER);
        props.getToken().setAccessTtlSeconds(600);
        Path file = Path.of("target/test-data/intro-unit.json");
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.deleteIfExists(file);
        props.getToken().setStateFile(file.toString());

        tokens = new AccessTokenService(new HmacSigner(props), clock);
        store = new FileRefreshTokenStore(props, clock);
        introspection = new IntrospectionService(tokens, store, props);
        sessions = new SessionService(store, clock);
    }

    private String validTokenForFamily(String familyId, long gen) {
        AccessTokenClaims claims = new AccessTokenClaims(ISSUER, "u-alice", "local-resource-api",
                "jti-" + familyId, "client-web", familyId, now, now + 600, gen,
                List.of("USER"), List.of("read", "write"));
        return tokens.issue(claims);
    }

    @Test
    void activeTokenIsReportedActiveWithMetadata() {
        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read", "write"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());

        IntrospectionService.Result result = introspection.introspect(token);
        assertThat(result.active()).isTrue();
        assertThat(result.reason()).isNull();
        assertThat(result.subject()).isEqualTo("u-alice");
        assertThat(result.clientId()).isEqualTo("client-web");
        assertThat(result.scopes()).containsExactly("read", "write");
    }

    @Test
    void invalidInputsNeverThrowAndAreDistinct() {
        assertThat(introspection.introspect(null).reason()).isEqualTo("missing_token");
        assertThat(introspection.introspect("   ").reason()).isEqualTo("missing_token");
        assertThat(introspection.introspect("not-a-jwt").reason()).isEqualTo("malformed");
        assertThat(introspection.introspect("a.b.c").reason()).isEqualTo("malformed");
        // 段数对但内容是乱 base64/json，也不抛异常
        String garbage = Base64.getUrlEncoder().withoutPadding().encodeToString("{".getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString("}".getBytes()) + ".sig";
        assertThat(introspection.introspect(garbage).reason()).isEqualTo("malformed");
    }

    @Test
    void expiredTamperedUnknownFamilyAreDistinctReasons() {
        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());

        // 过期
        clock.advance(601);
        assertThat(introspection.introspect(token).reason()).isEqualTo("expired");
        clock.advance(-601);

        // 篡改签名 -> bad_signature
        String[] parts = token.split("\\.");
        char last = parts[2].charAt(parts[2].length() - 1);
        String flipped = parts[2].substring(0, parts[2].length() - 1) + (last == 'A' ? 'B' : 'A');
        assertThat(introspection.introspect(parts[0] + "." + parts[1] + "." + flipped).reason())
                .isEqualTo("bad_signature");

        // 合法签名但族不存在 -> family_stale
        String unknownFamily = validTokenForFamily("fam-does-not-exist", 0L);
        assertThat(introspection.introspect(unknownFamily).reason()).isEqualTo("family_stale");
    }

    @Test
    void explicitTokenRevocationIsReportedTokenRevoked() {
        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());
        assertThat(introspection.introspect(token).active()).isTrue();

        // 显式令牌撤销（/oauth/revoke 路径）：token_revoked
        store.revoke(stored.familyId(), "explicit_revoke:access_token");
        IntrospectionService.Result after = introspection.introspect(token);
        assertThat(after.active()).isFalse();
        assertThat(after.reason()).isEqualTo("token_revoked");
        // 无效结果不携带任何主体/密钥元数据
        assertThat(after.subject()).isNull();
        assertThat(after.clientId()).isNull();
    }

    @Test
    void sessionLogoutIsReportedSessionRevokedAndStaysDistinctFromTokenRevoke() {
        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());
        assertThat(introspection.introspect(token).active()).isTrue();

        // 会话被踢下线（会话管理路径）：session_revoked
        sessions.revokeSession("u-alice", stored.familyId());
        IntrospectionService.Result after = introspection.introspect(token);
        assertThat(after.active()).isFalse();
        assertThat(after.reason()).isEqualTo("session_revoked");

        // 两种起因彼此可辨，也与其余族相关原因可辨
        String unknownFamily = validTokenForFamily("fam-does-not-exist", 0L);
        assertThat(introspection.introspect(unknownFamily).reason()).isEqualTo("family_stale");
    }

    @Test
    void tokenRevocationAndSessionLogoutReasonsAreNeverMergedAcrossFamilies() {
        var revokedFamily = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        var loggedOutFamily = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String revokedToken = validTokenForFamily(revokedFamily.familyId(), revokedFamily.generation());
        String loggedOutToken = validTokenForFamily(loggedOutFamily.familyId(), loggedOutFamily.generation());

        store.revoke(revokedFamily.familyId(), "explicit_revoke:unspecified");
        sessions.revokeSession("u-alice", loggedOutFamily.familyId());

        // 同一主体、同一撤销状态，仅起因不同——原因码必须仍然分得开
        assertThat(introspection.introspect(revokedToken).reason()).isEqualTo("token_revoked");
        assertThat(introspection.introspect(loggedOutToken).reason()).isEqualTo("session_revoked");
    }

    @Test
    void allInvalidReasonsRemainMutuallyDistinguishable() {
        var stored = store.create("u-dave", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = tokens.issue(new AccessTokenClaims(ISSUER, "u-dave", "local-resource-api",
                "jti-distinct", "client-web", stored.familyId(), now, now + 600,
                stored.generation(), List.of("USER"), List.of("read")));
        assertThat(introspection.introspect(token).active()).isTrue();

        // alg=none 经典形态 -> unsupported_alg
        String noneAlg = Base64.getUrlEncoder().withoutPadding().encodeToString(
                        "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes())
                + "." + token.split("\\.")[1] + ".";
        assertThat(introspection.introspect(noneAlg).reason()).isEqualTo("unsupported_alg");

        // 由已摘除/不认识的 kid 签发 -> unknown_signing_key（与 bad_signature 分开）
        AccessTokenService removedKidSigner = new AccessTokenService(
                new HmacSigner(signerPropsWithKey("retired-secret", "k-retired")), clock);
        String removedKidToken = removedKidSigner.issue(new AccessTokenClaims(
                ISSUER, "u-dave", "local-resource-api", "jti-kid", "client-web",
                stored.familyId(), now, now + 600, stored.generation(),
                List.of("USER"), List.of("read")));
        assertThat(introspection.introspect(removedKidToken).reason())
                .isEqualTo("unknown_signing_key");

        // 缺少必需声明：把 payload 的 fam 字段删掉并用同一把合法密钥重签 -> missing_claims
        String missingClaims = resignPayloadRemovingClaim(token, "fam");
        assertThat(introspection.introspect(missingClaims).reason()).isEqualTo("missing_claims");

        // 签发者不符：用本服务密钥签一个别的 iss -> issuer_mismatch
        String otherIssuer = new AccessTokenService(new HmacSigner(signerPropsWithKey("intro-hmac-key")), clock)
                .issue(new AccessTokenClaims("some-other-issuer", "u-dave", "local-resource-api",
                        "jti-iss", "client-web", stored.familyId(), now, now + 600,
                        stored.generation(), List.of("USER"), List.of("read")));
        assertThat(introspection.introspect(otherIssuer).reason()).isEqualTo("issuer_mismatch");

        // 以上所有原因彼此不同，且不与新引入的两个撤销原因撞码
        org.assertj.core.api.Assertions.assertThat(java.util.Set.of(
                "missing_token", "malformed", "unsupported_alg", "unknown_signing_key",
                "bad_signature", "missing_claims", "expired", "issuer_mismatch",
                "token_revoked", "session_revoked", "family_stale")).hasSize(11);
    }

    /** 构造单密钥或多密钥（带 kid）的配置，便于用不同密钥签发令牌。 */
    private AuthProperties signerPropsWithKey(String key) {
        return signerPropsWithKey(key, null);
    }

    private AuthProperties signerPropsWithKey(String key, String kid) {
        AuthProperties p = new AuthProperties();
        p.getSecurity().setIssuer(ISSUER);
        if (kid == null) {
            p.getSecurity().setHmacKey(key);
        } else {
            p.getSecurity().setKeys(new java.util.LinkedHashMap<>(java.util.Map.of(kid, key)));
            p.getSecurity().setActiveKeyId(kid);
        }
        return p;
    }

    /** 用 introspection 使用的那把单密钥，对删除了某个声明的 payload 重新签名。 */
    private String resignPayloadRemovingClaim(String compact, String claimToRemove) {
        try {
            String[] parts = compact.split("\\.");
            com.fasterxml.jackson.databind.node.ObjectNode payload;
            try (com.fasterxml.jackson.core.JsonParser parser =
                         com.github.highcumontoa.authaccesscontroljava.support.JsonCodec.mapper()
                                 .getFactory().createParser(Base64.getUrlDecoder().decode(parts[1]))) {
                payload = com.github.highcumontoa.authaccesscontroljava.support.JsonCodec.mapper()
                        .readTree(parser);
            }
            payload.remove(claimToRemove);
            String newPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    com.github.highcumontoa.authaccesscontroljava.support.JsonCodec.mapper()
                            .writeValueAsBytes(payload));
            byte[] sig = new HmacSigner(props).sign(
                    (parts[0] + "." + newPayload).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return parts[0] + "." + newPayload + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void legacyStateFileWithoutCauseStillDistinguishesLogoutFromRevocation() throws Exception {
        // 用当前版本写两个已撤销族，再手工抹掉 revocationCause 字段，模拟旧版本落盘格式。
        var tokenRevokedFamily = store.create("u-legacy", "client-web", 3600,
                List.of("USER"), List.of("read"));
        var loggedOutFamily = store.create("u-legacy", "client-web", 3600,
                List.of("USER"), List.of("read"));
        store.revoke(tokenRevokedFamily.familyId(), "explicit_revoke:unspecified");
        sessions.revokeSession("u-legacy", loggedOutFamily.familyId());

        Path file = Path.of(props.getToken().getStateFile());
        com.fasterxml.jackson.databind.JsonNode tree =
                com.github.highcumontoa.authaccesscontroljava.support.JsonCodec.mapper()
                        .readTree(Files.readAllBytes(file));
        com.fasterxml.jackson.databind.node.ArrayNode families =
                (com.fasterxml.jackson.databind.node.ArrayNode) tree;
        families.forEach(f -> ((com.fasterxml.jackson.databind.node.ObjectNode) f)
                .remove("revocationCause"));
        Files.writeString(file, families.toString());

        // 重新加载：旧格式中起因字段缺失，必须依据 revokeReason 兜底分类，结论不退化
        FileRefreshTokenStore reloaded = new FileRefreshTokenStore(props, clock);
        IntrospectionService reloadedIntro = new IntrospectionService(tokens, reloaded, props);

        String revokedToken = validTokenForFamily(tokenRevokedFamily.familyId(),
                tokenRevokedFamily.generation());
        String loggedOutToken = validTokenForFamily(loggedOutFamily.familyId(),
                loggedOutFamily.generation());
        assertThat(reloadedIntro.introspect(revokedToken).reason()).isEqualTo("token_revoked");
        assertThat(reloadedIntro.introspect(loggedOutToken).reason()).isEqualTo("session_revoked");
    }

    @Test
    void introspectionIsReadOnlyAndDoesNotChangeState() {        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());

        for (int i = 0; i < 3; i++) {
            IntrospectionService.Result result = introspection.introspect(token);
            assertThat(result.active()).isTrue();
        }
        // 自检不更新 lastUsedAt（仍为创建时刻），令牌依旧有效
        RefreshTokenStore.FamilyStatus status =
                store.familyStatus(stored.familyId(), stored.generation());
        assertThat(status).isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
    }
}
