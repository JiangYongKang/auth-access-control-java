package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.session.SessionService;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** 经 SessionService 注销：并发/重复恰好一次成功，其余 session_not_found；不牵连其它会话。 */
class SessionServiceTest {

    static class FixedClock extends Clock {
        private final long seconds;
        FixedClock(long seconds) { this.seconds = seconds; }
        @Override public Instant now() { return Instant.ofEpochSecond(seconds); }
    }

    private FileRefreshTokenStore store;
    private SessionService sessions;
    private RefreshTokenStore.StoredToken target;
    private RefreshTokenStore.StoredToken keep;

    @BeforeEach
    void setUp() throws Exception {
        Path file = Path.of("target/test-data/session-service-unit.json");
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.deleteIfExists(file);
        AuthProperties props = new AuthProperties();
        props.getToken().setStateFile(file.toString());
        Clock clock = new FixedClock(1_700_000_000L);
        store = new FileRefreshTokenStore(props, clock);
        sessions = new SessionService(store);
        target = store.create("u-alice", "client-web", 3600, List.of("USER"), List.of("read"));
        keep = store.create("u-alice", "client-mobile", 3600, List.of("USER"), List.of("read"));
    }

    @Test
    void firstRevokeSucceedsAndRepeatsReportSessionNotFound() {
        sessions.revokeSession("u-alice", target.familyId());

        // 立即生效：该会话此前发出的访问令牌所属族为 REVOKED
        assertThat(store.familyStatus(target.familyId(), target.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);

        // 重复注销：明确告知会话不存在/已注销，而不是再次成功
        assertThatThrownBy(() -> sessions.revokeSession("u-alice", target.familyId()))
                .isInstanceOf(RejectException.class)
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.SESSION_NOT_FOUND);

        // 同主体另一个会话不受牵连
        assertThat(store.familyStatus(keep.familyId(), keep.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
        assertThat(sessions.listSessions("u-alice"))
                .extracting(s -> s.sessionId()).containsExactly(keep.familyId());
    }

    @Test
    void unknownWrongSubjectAndBlankSessionAreRejected() {
        assertThatThrownBy(() -> sessions.revokeSession("u-alice", "no-such-session"))
                .isInstanceOf(RejectException.class)
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.SESSION_NOT_FOUND);
        assertThatThrownBy(() -> sessions.revokeSession("u-bob", target.familyId()))
                .isInstanceOf(RejectException.class)
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.SESSION_NOT_FOUND);
        assertThatThrownBy(() -> sessions.revokeSession("u-alice", "  "))
                .isInstanceOf(RejectException.class)
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.INVALID_REQUEST);
        // 被跨主体尝试注销后，真正的主体仍能注销成功
        sessions.revokeSession("u-alice", target.familyId());
    }

    @Test
    void concurrentRevokesSucceedExactlyOnce() throws Exception {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger notFound = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    sessions.revokeSession("u-alice", target.familyId());
                    ok.incrementAndGet();
                } catch (RejectException ex) {
                    if (ex.reason() == RejectReason.SESSION_NOT_FOUND) {
                        notFound.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        assertThat(ok.get()).isEqualTo(1);
        assertThat(notFound.get()).isEqualTo(threads - 1);
        assertThat(store.familyStatus(target.familyId(), target.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
        assertThat(store.revocationCause(target.familyId()))
                .isEqualTo(RefreshTokenStore.RevocationCause.SESSION_LOGOUT);
        assertThat(store.familyStatus(keep.familyId(), keep.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
    }
}
