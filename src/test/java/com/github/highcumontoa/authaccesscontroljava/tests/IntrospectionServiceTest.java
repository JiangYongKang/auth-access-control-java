package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.session.IntrospectionService;
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
    void revokedSessionIsReportedSessionRevoked() {
        var stored = store.create("u-alice", "client-web", 3600,
                List.of("USER"), List.of("read"));
        String token = validTokenForFamily(stored.familyId(), stored.generation());
        assertThat(introspection.introspect(token).active()).isTrue();

        store.revoke(stored.familyId(), "admin_session_logout");
        IntrospectionService.Result after = introspection.introspect(token);
        assertThat(after.active()).isFalse();
        assertThat(after.reason()).isEqualTo("session_revoked");
    }

    @Test
    void introspectionIsReadOnlyAndDoesNotChangeState() {
        var stored = store.create("u-alice", "client-web", 3600,
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
