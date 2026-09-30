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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * 会话模型并发语义：
 * 同一主体在不同客户端登录形成不同会话；并发「注销单个会话」不会牵连其它会话，
 * 「注销全部」对每个会话只生效一次，且已注销会话的访问令牌状态立即变为 REVOKED。
 */
class SessionConcurrencyTest {

    static class FixedClock extends Clock {
        private long seconds;
        FixedClock(long seconds) { this.seconds = seconds; }
        void advance(long d) { seconds += d; }
        @Override public Instant now() { return Instant.ofEpochSecond(seconds); }
    }

    private FileRefreshTokenStore newStore(Path file, Clock clock) {
        AuthProperties props = new AuthProperties();
        props.getToken().setStateFile(file.toString());
        return new FileRefreshTokenStore(props, clock);
    }

    @Test
    void distinctLoginsCreateIndependentSessionsAndListingHidesRevoked() throws Exception {
        Path file = Path.of("target/test-data/session-unit.json");
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.deleteIfExists(file);
        FixedClock clock = new FixedClock(1_700_000_000L);
        FileRefreshTokenStore store = newStore(file, clock);

        var s1 = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));
        clock.advance(5);
        var s2 = store.create("u-alice", "client-mobile", 3600, List.of("USER"), List.of("read"));
        clock.advance(5);
        var other = store.create("u-bob", "client-web", 3600, List.of("USER"), List.of("read"));

        List<RefreshFamily> sessions = store.listActiveSessions("u-alice");
        assertThat(sessions).extracting(RefreshFamily::getFamilyId)
                .containsExactly(s1.familyId(), s2.familyId());
        assertThat(sessions).extracting(RefreshFamily::getClientId)
                .containsExactly("client-web", "client-mobile");

        // 注销其中一个会话：另一个仍然有效，且不影响 bob
        store.revoke(s1.familyId(), "admin_session_logout");
        assertThat(store.familyStatus(s1.familyId(), s1.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
        assertThat(store.familyStatus(s2.familyId(), s2.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
        assertThat(store.listActiveSessions("u-alice"))
                .extracting(RefreshFamily::getFamilyId).containsExactly(s2.familyId());
        assertThat(store.listActiveSessions("u-bob"))
                .extracting(RefreshFamily::getFamilyId).containsExactly(other.familyId());
    }

    @Test
    void concurrentRevokeSingleSessionTakesEffectImmediatelyAndExactlyOnce() throws Exception {
        Path file = Path.of("target/test-data/session-concurrent-one.json");
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.deleteIfExists(file);
        FixedClock clock = new FixedClock(1_700_000_000L);
        FileRefreshTokenStore store = newStore(file, clock);

        var target = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));
        var keep = store.create("u-alice", "client-mobile", 3600, List.of("USER"), List.of("read"));

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    store.revoke(target.familyId(), "concurrent_logout");
                    if (store.familyStatus(target.familyId(), target.generation())
                            == RefreshTokenStore.FamilyStatus.REVOKED) {
                        ok.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        // 所有线程都观察到目标会话已撤销（幂等、即时）；同主体另一个会话不受牵连
        assertThat(ok.get()).isEqualTo(threads);
        assertThat(store.familyStatus(target.familyId(), target.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
        assertThat(store.familyStatus(keep.familyId(), keep.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
    }

    @Test
    void revokeAllSessionsUnderConcurrencyRevokesEachExactlyOnce() throws Exception {
        Path file = Path.of("target/test-data/session-concurrent-all.json");
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.deleteIfExists(file);
        FixedClock clock = new FixedClock(1_700_000_000L);
        FileRefreshTokenStore store = newStore(file, clock);

        int sessionCount = 10;
        RefreshTokenStore.StoredToken[] sessions = new RefreshTokenStore.StoredToken[sessionCount];
        for (int i = 0; i < sessionCount; i++) {
            sessions[i] = store.create("u-alice", "client-" + i, 3600,
                    List.of("USER"), List.of("read"));
        }

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    store.revokeSessionsBySubject("u-alice", "logout_all");
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        // 第一次撤销 10 个；之后并发的重复调用必须返回 0（不能重复计数/重复落盘）
        assertThat(store.revokeSessionsBySubject("u-alice", "logout_all")).isZero();
        assertThat(store.listActiveSessions("u-alice")).isEmpty();
        for (RefreshTokenStore.StoredToken s : sessions) {
            assertThat(store.familyStatus(s.familyId(), s.generation()))
                    .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
        }
    }
}
