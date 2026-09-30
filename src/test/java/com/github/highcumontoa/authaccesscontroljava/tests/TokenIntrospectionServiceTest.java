package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.SigningKeyRing;
import com.github.highcumontoa.authaccesscontroljava.token.TokenAuthService;
import com.github.highcumontoa.authaccesscontroljava.token.TokenIntrospectionService;
import com.github.highcumontoa.authaccesscontroljava.domain.AccountDirectory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenIntrospectionServiceTest {

    static class FixedClock extends Clock {
        private volatile long seconds = 1_700_000_000L;

        void advance(long delta) {
            seconds += delta;
        }

        @Override
        public Instant now() {
            return Instant.ofEpochSecond(seconds);
        }
    }

    private static final String ISSUER = "test-issuer";

    private Path stateFile;
    private FixedClock clock;
    private FileRefreshTokenStore store;
    private AccessTokenService accessTokens;
    private TokenAuthService tokenAuth;
    private TokenIntrospectionService introspection;

    @BeforeEach
    void setUp() throws Exception {
        stateFile = Files.createTempFile("intro-test", ".json");
        Files.delete(stateFile);
        clock = new FixedClock();
        AuthProperties props = new AuthProperties();
        props.getSecurity().setHmacKey("intro-hmac-key-0123456789");
        props.getSecurity().setIssuer(ISSUER);
        props.getToken().setStateFile(stateFile.toString());
        props.getToken().setAccessTtlSeconds(600);
        SigningKeyRing ring = new SigningKeyRing(props);
        accessTokens = new AccessTokenService(ring, clock);
        store = new FileRefreshTokenStore(props, clock);
        tokenAuth = new TokenAuthService(accessTokens, store, ring, new AccountDirectory(), props, clock);
        introspection = new TokenIntrospectionService(accessTokens, store);
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(stateFile);
    }

    private String passwordToken() {
        return tokenAuth.passwordGrant("client-web", "web-secret", "alice", "alice-pass-123", null)
                .accessToken();
    }

    @Test
    void validTokenIsActiveAndExposesNoRawToken() {
        String token = passwordToken();
        TokenIntrospectionService.Result r = introspection.introspect(token, ISSUER);

        assertThat(r.active()).isTrue();
        assertThat(r.reason()).isNull();
        assertThat(r.subject()).isEqualTo("u-alice");
        assertThat(r.clientId()).isEqualTo("client-web");
        assertThat(r.sessionId()).isNotBlank();
        assertThat(r.exp()).isEqualTo(clock.epochSeconds() + 600);
        assertThat(r.scopes()).containsExactly("read", "write");
    }

    @Test
    void introspectionDoesNotMutateState() {
        String token = passwordToken();
        long genBefore = store.listBySubject("u-alice").get(0).getGeneration();
        long usedBefore = store.listBySubject("u-alice").get(0).getLastUsedAt();
        clock.advance(120);

        introspection.introspect(token, ISSUER);
        introspection.introspect(token, ISSUER);

        var family = store.listBySubject("u-alice").get(0);
        assertThat(family.getGeneration()).isEqualTo(genBefore);
        // 自检不更新"最近使用"时间（认证路径才更新）。
        assertThat(family.getLastUsedAt()).isEqualTo(usedBefore);
        assertThat(introspection.introspect(token, ISSUER).active()).isTrue();
    }

    @Test
    void garbageInputsAreInactiveWithoutThrowing() {
        for (String bad : List.of("", "   ", "not-a-jwt", "a.b", "a.b.c", "a..c",
                "@@@.###.$$$", "null", "{not-json}")) {
            TokenIntrospectionService.Result r = introspection.introspect(bad, ISSUER);
            assertThat(r.active())
                    .as("input=%s should be inactive", bad)
                    .isFalse();
            assertThat(r.reason()).isNotBlank();
            assertThat(r.subject()).isNull();
        }
        assertThat(introspection.introspect(null, ISSUER).reason())
                .isEqualTo(RejectReason.MISSING_TOKEN.errorCode());
    }

    @Test
    void expiredTokenReportsExpired() {
        String token = passwordToken();
        clock.advance(601);
        assertThat(introspection.introspect(token, ISSUER).reason())
                .isEqualTo(RejectReason.TOKEN_EXPIRED.errorCode());
    }

    @Test
    void revokedSessionReportsSessionLoggedOut() {
        String token = passwordToken();
        String sessionId = store.listBySubject("u-alice").get(0).getFamilyId();
        store.logoutSession(sessionId, com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason.SESSION_REVOKED);

        TokenIntrospectionService.Result r = introspection.introspect(token, ISSUER);
        assertThat(r.active()).isFalse();
        assertThat(r.reason()).isEqualTo(RejectReason.TOKEN_SESSION_LOGGED_OUT.errorCode());
    }

    @Test
    void revokedFamilyReportsRevoked() {
        var issued = tokenAuth.passwordGrant("client-web", "web-secret", "alice", "alice-pass-123", null);
        tokenAuth.revokeGrant("client-web", "web-secret", issued.refreshToken(), "refresh_token");

        assertThat(introspection.introspect(issued.accessToken(), ISSUER).reason())
                .isEqualTo(RejectReason.TOKEN_FAMILY_REVOKED.errorCode());
    }

    @Test
    void tamperedSignatureReportsBadSignature() {
        String token = passwordToken();
        String flipped = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "B" : "A");
        assertThat(introspection.introspect(flipped, ISSUER).reason())
                .isEqualTo(RejectReason.BAD_SIGNATURE.errorCode());
    }

    @Test
    void tokenFromRemovedKeyReportsUnknownSigningKey() {
        // 用显式多密钥环境签发（kid=k-a）。
        AuthProperties multiProps = new AuthProperties();
        multiProps.getSecurity().setIssuer(ISSUER);
        multiProps.getSecurity().getSigningKeys().put("k-a", "key-a-secret-0123456789");
        multiProps.getSecurity().getSigningKeys().put("k-b", "key-b-secret-0123456789");
        multiProps.getSecurity().setActiveKeyId("k-a");
        multiProps.getToken().setStateFile(stateFile.toString());
        multiProps.getToken().setAccessTtlSeconds(600);
        SigningKeyRing multiRing = new SigningKeyRing(multiProps);
        AccessTokenService multiAccess = new AccessTokenService(multiRing, clock);
        TokenAuthService multiAuth =
                new TokenAuthService(multiAccess, store, multiRing, new AccountDirectory(), multiProps, clock);
        String token = multiAuth.passwordGrant("client-web", "web-secret", "alice", "alice-pass-123", null)
                .accessToken();

        // 密钥仍保留（k-a、k-b 都在）：active。
        TokenIntrospectionService multiIntro = new TokenIntrospectionService(multiAccess, store);
        assertThat(multiIntro.introspect(token, ISSUER).active()).isTrue();

        // 模拟运维摘掉 k-a 后的新进程（只保留 k-b）：kid 不认识 → unknown_signing_key。
        AuthProperties reduced = new AuthProperties();
        reduced.getSecurity().setIssuer(ISSUER);
        reduced.getSecurity().getSigningKeys().put("k-b", "key-b-secret-0123456789");
        reduced.getSecurity().setActiveKeyId("k-b");
        SigningKeyRing reducedRing = new SigningKeyRing(reduced);
        AccessTokenService reducedAccess = new AccessTokenService(reducedRing, clock);
        TokenIntrospectionService reducedIntro = new TokenIntrospectionService(reducedAccess, store);

        assertThat(reducedIntro.introspect(token, ISSUER).reason())
                .isEqualTo(RejectReason.UNKNOWN_SIGNING_KEY.errorCode());

        // 另一把保留密钥签发的令牌不受影响：仍 active。
        AuthProperties reducedActiveB = new AuthProperties();
        reducedActiveB.getSecurity().setIssuer(ISSUER);
        reducedActiveB.getSecurity().getSigningKeys().put("k-b", "key-b-secret-0123456789");
        reducedActiveB.getSecurity().setActiveKeyId("k-b");
        reducedActiveB.getToken().setStateFile(stateFile.toString());
        reducedActiveB.getToken().setAccessTtlSeconds(600);
        SigningKeyRing ringB = new SigningKeyRing(reducedActiveB);
        AccessTokenService accessB = new AccessTokenService(ringB, clock);
        TokenAuthService authB = new TokenAuthService(
                accessB, store, ringB, new AccountDirectory(), reducedActiveB, clock);
        String tokenB = authB.passwordGrant("client-web", "web-secret", "bob", "bob-pass-123", null)
                .accessToken();
        assertThat(new TokenIntrospectionService(accessB, store).introspect(tokenB, ISSUER).active())
                .isTrue();
    }
}
