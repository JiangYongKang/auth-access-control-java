package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshFamily;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RefreshTokenStoreTest {

    static class FixedClock extends Clock {
        private volatile long seconds;

        FixedClock(long seconds) {
            this.seconds = seconds;
        }

        void advance(long delta) {
            seconds += delta;
        }

        @Override
        public Instant now() {
            return Instant.ofEpochSecond(seconds);
        }
    }

    private AuthProperties props(Path stateFile) {
        AuthProperties props = new AuthProperties();
        props.getToken().setStateFile(stateFile.toString());
        return props;
    }

    @Test
    void rotationProducesNewTokenAndInvalidatesOld(@TempDir Path dir) {
        FixedClock clock = new FixedClock(1_700_000_000L);
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")), clock);

        var stored = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));
        var first = store.consume(stored.rawToken(), "client-web");
        assertThat(first.outcome()).isEqualTo(RefreshTokenStore.RotationOutcome.SUCCESS);
        assertThat(first.nextToken().rawToken()).isNotEqualTo(stored.rawToken());
        assertThat(first.nextToken().generation()).isEqualTo(1);

        // 旧令牌再次使用必须被识别为重放
        var replay = store.consume(stored.rawToken(), "client-web");
        assertThat(replay.outcome()).isEqualTo(RefreshTokenStore.RotationOutcome.REPLAYED);
        assertThat(replay.nextToken()).isNull();

        // 新令牌可继续轮换
        var second = store.consume(first.nextToken().rawToken(), "client-web");
        assertThat(second.outcome()).isEqualTo(RefreshTokenStore.RotationOutcome.SUCCESS);
        assertThat(second.nextToken().generation()).isEqualTo(2);
    }

    @Test
    void concurrentReuseAllowsExactlyOneSuccess(@TempDir Path dir) throws Exception {
        FixedClock clock = new FixedClock(1_700_000_000L);
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")), clock);
        var stored = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<RefreshTokenStore.RotationOutcome> outcomes = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(store.consume(stored.rawToken(), "client-web").outcome());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(20, TimeUnit.SECONDS)).isTrue();

        assertThat(outcomes).containsExactlyInAnyOrder(
                RefreshTokenStore.RotationOutcome.SUCCESS,
                RefreshTokenStore.RotationOutcome.REPLAYED);
    }

    @Test
    void unknownAndMalformedTokensAreRejected(@TempDir Path dir) {
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")),
                new FixedClock(1_700_000_000L));
        assertThat(store.consume("not-a-valid-token", "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.UNKNOWN);
        assertThat(store.consume("family-without-secret", "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.UNKNOWN);
        assertThat(store.consume("deadbeef-dead." + "a".repeat(64), "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.UNKNOWN);
    }

    @Test
    void clientMismatchIsDistinctFromReplay(@TempDir Path dir) {
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")),
                new FixedClock(1_700_000_000L));
        var stored = store.create("u-alice", "client-web", 3600, List.of(), List.of());

        var mismatch = store.consume(stored.rawToken(), "client-other");
        assertThat(mismatch.outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.CLIENT_MISMATCH);
        // 客户端不符不得消费令牌：原客户端仍能成功轮换一次
        var legit = store.consume(stored.rawToken(), "client-web");
        assertThat(legit.outcome()).isEqualTo(RefreshTokenStore.RotationOutcome.SUCCESS);
    }

    @Test
    void expiredFamilyRejectsRefresh(@TempDir Path dir) {
        FixedClock clock = new FixedClock(1_700_000_000L);
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")), clock);
        var stored = store.create("u-alice", "client-web", 100, List.of(), List.of());

        clock.advance(101);
        assertThat(store.consume(stored.rawToken(), "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.EXPIRED);
    }

    @Test
    void revokedFamilyRejectsRefreshAndPersistsAcrossRestart(@TempDir Path dir) {
        Path file = dir.resolve("state.json");
        FixedClock clock = new FixedClock(1_700_000_000L);
        var store = new FileRefreshTokenStore(props(file), clock);
        var stored = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));

        store.revoke(stored.familyId(), "test-revoke");
        assertThat(store.consume(stored.rawToken(), "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.REVOKED);

        // 模拟进程重启：用同一文件新建存储实例
        var restarted = new FileRefreshTokenStore(props(file), clock);
        assertThat(restarted.consume(stored.rawToken(), "client-web").outcome())
                .isEqualTo(RefreshTokenStore.RotationOutcome.REVOKED);
        RefreshFamily family = restarted.findByFamilyId(stored.familyId()).orElseThrow();
        assertThat(family.isRevoked()).isTrue();
        assertThat(family.getRevokeReason()).isEqualTo("test-revoke");
        assertThat(family.getRoles()).containsExactly("USER");
        assertThat(family.getScopes()).containsExactly("read");
    }

    @Test
    void persistedFileContainsOnlyHashesNoRawTokens(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("state.json");
        var store = new FileRefreshTokenStore(props(file), new FixedClock(1_700_000_000L));
        var stored = store.create("u-alice", "client-web", 3600, List.of(), List.of("read"));

        String json = Files.readString(file);
        assertThat(json).doesNotContain(stored.rawToken());
        assertThat(json).contains("currentTokenHash");
        assertThat(json).contains("\"revoked\" : false");
    }

    @Test
    void familyStatusReflectsGenerationAndRevocation(@TempDir Path dir) {
        var store = new FileRefreshTokenStore(props(dir.resolve("state.json")),
                new FixedClock(1_700_000_000L));
        var stored = store.create("u-alice", "client-web", 3600, List.of(), List.of());

        assertThat(store.familyStatus(stored.familyId(), 0))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);

        var rotated = store.consume(stored.rawToken(), "client-web");
        // 旧代访问令牌应得到 ACTIVE_STALE
        assertThat(store.familyStatus(stored.familyId(), 0))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_STALE);
        assertThat(store.familyStatus(stored.familyId(), rotated.nextToken().generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);

        store.revoke(stored.familyId(), "r");
        assertThat(store.familyStatus(stored.familyId(), 1))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
        assertThat(store.familyStatus("nonexistent", 0))
                .isEqualTo(RefreshTokenStore.FamilyStatus.UNKNOWN);
    }

    @Test
    void revocationCausePersistsAndLegacyRevokedRecordsDefaultToTokenRevocation(@TempDir Path dir)
            throws Exception {
        Path file = dir.resolve("state.json");
        FixedClock clock = new FixedClock(1_700_000_000L);
        FileRefreshTokenStore store = new FileRefreshTokenStore(props(file), clock);
        var byToken = store.create("u-alice", "client-web", 3600, List.of(), List.of("read"));
        var bySession = store.create("u-bob", "client-web", 3600, List.of(), List.of("read"));
        store.revoke(byToken.familyId(), "explicit_revoke:access_token");
        assertThat(store.revokeSession(bySession.familyId(), "u-bob", "admin_session_logout"))
                .isTrue();

        // 重启后起因仍可辨
        FileRefreshTokenStore restarted = new FileRefreshTokenStore(props(file), clock);
        assertThat(restarted.revocationCause(byToken.familyId()))
                .isEqualTo(RefreshTokenStore.RevocationCause.TOKEN_REVOCATION);
        assertThat(restarted.revocationCause(bySession.familyId()))
                .isEqualTo(RefreshTokenStore.RevocationCause.SESSION_LOGOUT);
        assertThat(restarted.revocationCause("missing-family")).isNull();

        // 历史版本落盘的记录没有 revocationCause 字段：revoked=true 时按显式令牌撤销解释
        String legacy = Files.readString(file)
                .replace(",\n  \"revocationCause\" : \"TOKEN_REVOCATION\"", "")
                .replace(",\n  \"revocationCause\" : \"SESSION_LOGOUT\"", "");
        assertThat(legacy).doesNotContain("revocationCause");
        Files.writeString(file, legacy);
        FileRefreshTokenStore legacyStore = new FileRefreshTokenStore(props(file), clock);
        assertThat(legacyStore.revocationCause(byToken.familyId()))
                .isEqualTo(RefreshTokenStore.RevocationCause.TOKEN_REVOCATION);
        assertThat(legacyStore.revocationCause(bySession.familyId()))
                .isEqualTo(RefreshTokenStore.RevocationCause.TOKEN_REVOCATION);
    }
}
