package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason;
import com.github.highcumontoa.authaccesscontroljava.session.SessionOverview;
import com.github.highcumontoa.authaccesscontroljava.session.SessionService;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshFamily;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SessionServiceTest {

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

    private Path stateFile;
    private FixedClock clock;
    private FileRefreshTokenStore store;
    private SessionService sessions;

    @BeforeEach
    void setUp() throws Exception {
        stateFile = Files.createTempFile("session-test", ".json");
        Files.delete(stateFile);
        clock = new FixedClock();
        AuthProperties props = new AuthProperties();
        props.getToken().setStateFile(stateFile.toString());
        store = new FileRefreshTokenStore(props, clock);
        sessions = new SessionService(store, clock);
    }

    @AfterEach
    void tearDown() throws Exception {
        Files.deleteIfExists(stateFile);
    }

    private RefreshTokenStore.StoredToken login(String subject, String clientId) {
        return store.create(subject, clientId, 3600, List.of("USER"), List.of("read"));
    }

    @Test
    void sameUserOnDifferentClientsYieldsIndependentSessions() {
        RefreshTokenStore.StoredToken web = login("u-alice", "client-web");
        clock.advance(10);
        RefreshTokenStore.StoredToken mobile = login("u-alice", "client-readonly");
        clock.advance(10);

        List<SessionOverview> list = sessions.listActiveSessions("u-alice");
        assertThat(list).hasSize(2);
        assertThat(list).extracting(SessionOverview::sessionId)
                .containsExactly(web.familyId(), mobile.familyId());
        // 概览不暴露任何令牌原文；能看出客户端、建立时间、最近使用时间。
        SessionOverview first = list.get(0);
        assertThat(first.clientId()).isEqualTo("client-web");
        assertThat(first.createdAt()).isLessThan(list.get(1).createdAt());
        assertThat(first.lastUsedAt()).isGreaterThanOrEqualTo(first.createdAt());
        assertThat(first.expiresAt()).isEqualTo(first.createdAt() + 3600);
    }

    @Test
    void loggingOutOneSessionDoesNotAffectTheOthers() {
        RefreshTokenStore.StoredToken web = login("u-alice", "client-web");
        RefreshTokenStore.StoredToken mobile = login("u-alice", "client-readonly");

        sessions.logoutSession("u-alice", web.familyId(), false);

        assertThat(sessions.listActiveSessions("u-alice"))
                .extracting(SessionOverview::sessionId)
                .containsExactly(mobile.familyId());
        // 已注销会话的访问令牌立即失效，且原因为"会话被注销"。
        assertThat(store.familyStatus(web.familyId(), web.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
        assertThat(store.findByFamilyId(web.familyId()).orElseThrow().getLogoutReason())
                .isEqualTo(SessionLogoutReason.SESSION_REVOKED);
        // 另一个会话仍有效。
        assertThat(store.familyStatus(mobile.familyId(), mobile.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
    }

    @Test
    void logoutAllOnlyAffectsTheTargetSubject() {
        RefreshTokenStore.StoredToken a1 = login("u-alice", "client-web");
        RefreshTokenStore.StoredToken a2 = login("u-alice", "client-readonly");
        RefreshTokenStore.StoredToken b1 = login("u-bob", "client-web");

        int count = sessions.logoutAll("u-alice");

        assertThat(count).isEqualTo(2);
        assertThat(sessions.listActiveSessions("u-alice")).isEmpty();
        assertThat(sessions.listActiveSessions("u-bob")).hasSize(1);
        assertThat(store.familyStatus(a1.familyId(), a1.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
        assertThat(store.familyStatus(a2.familyId(), a2.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
        assertThat(store.familyStatus(b1.familyId(), b1.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
        assertThat(store.findByFamilyId(a1.familyId()).orElseThrow().getLogoutReason())
                .isEqualTo(SessionLogoutReason.ALL_SESSIONS_REVOKED);
    }

    @Test
    void cannotLogoutAnotherSubjectsSessionAndMissingSessionIsDistinct() {
        RefreshTokenStore.StoredToken alice = login("u-alice", "client-web");

        // bob 试图注销 alice 的会话：归属错误。
        assertThatThrownBy(() -> sessions.logoutSession("u-bob", alice.familyId(), false))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.FORBIDDEN_OWNER));
        // 会话仍在。
        assertThat(sessions.listActiveSessions("u-alice")).hasSize(1);

        // 不存在的会话 ID：专门的 not_found 结论。
        assertThatThrownBy(() -> sessions.logoutSession("u-alice", "no-such-session", false))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.SESSION_NOT_FOUND));
    }

    @Test
    void adminCanLogoutAnotherSubjectsSession() {
        RefreshTokenStore.StoredToken alice = login("u-alice", "client-web");
        sessions.logoutSession("u-admin", alice.familyId(), true);
        assertThat(store.familyStatus(alice.familyId(), alice.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
    }

    @Test
    void revokedFamilyIsDistinguishedFromTokenRevoke() {
        RefreshTokenStore.StoredToken alice = login("u-alice", "client-web");
        store.revoke(alice.familyId(), "explicit_revoke:access_token");
        assertThat(store.familyStatus(alice.familyId(), alice.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.REVOKED);
    }

    @Test
    void concurrentLogoutOfSameSessionSucceedsAtMostOnce() throws Exception {
        RefreshTokenStore.StoredToken alice = login("u-alice", "client-web");
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger notFound = new AtomicInteger();
        AtomicInteger ok = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    sessions.logoutSession("u-alice", alice.familyId(), false);
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
        // 终态唯一且稳定。
        assertThat(store.familyStatus(alice.familyId(), alice.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
    }

    @Test
    void logoutSurvivesStoreRestartViaSameStateFile() {
        RefreshTokenStore.StoredToken alice = login("u-alice", "client-web");
        RefreshTokenStore.StoredToken bob = login("u-bob", "client-web");
        sessions.logoutSession("u-alice", alice.familyId(), false);
        sessions.logoutAll("u-bob");

        FileRefreshTokenStore reopened = new FileRefreshTokenStore(new AuthProperties() {{
            getToken().setStateFile(stateFile.toString());
        }}, clock);
        assertThat(reopened.familyStatus(alice.familyId(), alice.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
        assertThat(reopened.familyStatus(bob.familyId(), bob.generation()))
                .isEqualTo(RefreshTokenStore.FamilyStatus.LOGGED_OUT);
    }
}
