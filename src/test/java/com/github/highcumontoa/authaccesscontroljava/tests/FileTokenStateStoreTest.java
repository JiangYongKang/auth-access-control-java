package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.token.FileTokenStateStore;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshRejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshRejectedException;
import com.github.highcumontoa.authaccesscontroljava.token.TokenStateStore;

class FileTokenStateStoreTest {

    @TempDir
    Path tempDir;

    private Path storeFile;
    private AuthProperties properties;
    private MutableClock clock;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        storeFile = tempDir.resolve("token-state.json");
        properties = new AuthProperties();
        properties.getRefresh().setStorePath(storeFile.toString());
        properties.getRefresh().setTtl(Duration.ofMinutes(10));
        properties.getRefresh().setGraceWindow(Duration.ofMillis(100));
        clock = new MutableClock(Instant.parse("2026-09-23T00:00:00Z"));
        objectMapper = new ObjectMapper();
    }

    @AfterEach
    void tearDown() {
        assertFalse(Files.exists(storeFile.resolveSibling(storeFile.getFileName() + ".tmp")),
                "临时文件不应残留");
    }

    private FileTokenStateStore newStore() {
        return new FileTokenStateStore(properties, clock, objectMapper);
    }

    private String createFamily(FileTokenStateStore store, String hash) {
        long exp = clock.instant().toEpochMilli() + 600_000L;
        TokenStateStore.TokenState state = store.createFamily(
                "alice", "webapp", hash, "rjti-1", exp, "access-jti-1",
                List.of("profile:read"));
        return state.familyId();
    }

    @Test
    void rotateOnceSucceedsAndSecondSequentialUseIsReplay() {
        FileTokenStateStore store = newStore();
        String oldHash = "hash-old";
        createFamily(store, oldHash);

        TokenStateStore.RotationOutcome outcome = store.rotate(
                oldHash, "webapp", "hash-new", "rjti-2", clock.instant().toEpochMilli() + 600_000L,
                "access-jti-2");
        assertEquals("ROTATED", outcome.oldStatus());

        // 旧访问令牌立即进入拒绝清单
        assertTrue(store.isAccessDenied("access-jti-1"));
        assertFalse(store.isAccessDenied("access-jti-2"));

        // 宽限窗口之外再次使用旧令牌：重放攻击，家族被撤销
        clock.advance(Duration.ofMillis(500));
        RefreshRejectedException ex = assertThrows(RefreshRejectedException.class,
                () -> store.rotate(oldHash, "webapp", "x", "y", 0L, "z"));
        assertEquals(RefreshRejectReason.REPLAYED, ex.getReason());
        assertTrue(store.isAccessDenied("access-jti-2"), "重放后新访问令牌也应被拒绝");
        assertEquals("REVOKED", store.tokenStatus("hash-new"));
    }

    @Test
    void concurrentReuseOnlyOneSucceeds() throws Exception {
        // 用足够大的宽限窗口确保“并发复用”判定不被线程调度抖动影响
        properties.getRefresh().setGraceWindow(Duration.ofSeconds(10));
        FileTokenStateStore store = newStore();
        String oldHash = "hash-concurrent";
        createFamily(store, oldHash);

        int threads = 16;
        // 使用虚拟线程承载屏障等待，避免在平台线程受限环境下自死锁
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        List<RefreshRejectReason> rejectReasons = new ArrayList<>();
        List<Future<?>> futures = new ArrayList<>();

        try {
            for (int i = 0; i < threads; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    try {
                        store.rotate(oldHash, "webapp", "hash-new-" + idx, "rjti-" + idx,
                                clock.instant().toEpochMilli() + 600_000L, "access-" + idx);
                        success.incrementAndGet();
                    } catch (RefreshRejectedException expected) {
                        synchronized (rejectReasons) {
                            rejectReasons.add(expected.getReason());
                        }
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for (Future<?> f : futures) {
                f.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, success.get(), "并发轮换最多一次成功");
        assertEquals(threads - 1, rejectReasons.size(), "其余请求必须全部被拒绝");
        assertTrue(rejectReasons.stream().allMatch(RefreshRejectReason.CONCURRENT_REUSE::equals),
                "并发失败者原因必须可区分为 CONCURRENT_REUSE, 实际=" + rejectReasons);
        // 成功的轮换把旧访问令牌加入了拒绝清单
        assertTrue(store.isAccessDenied("access-jti-1"));
    }

    @Test
    void revokedFamilyRejectsEveryTokenAndPersistsAcrossRestart() throws Exception {
        FileTokenStateStore store = newStore();
        String oldHash = "hash-revoke";
        createFamily(store, oldHash);
        store.rotate(oldHash, "webapp", "hash-new", "rjti-2",
                clock.instant().toEpochMilli() + 600_000L, "access-jti-2");

        assertTrue(store.revokeFamily("hash-new", "webapp"));
        // 重复撤销返回 false
        assertFalse(store.revokeFamily("hash-new", "webapp"));

        // 旧/新刷新令牌均不可再用
        RefreshRejectedException oldEx = assertThrows(RefreshRejectedException.class,
                () -> store.rotate(oldHash, "webapp", "x", "y", 0L, "z"));
        assertEquals(RefreshRejectReason.REVOKED, oldEx.getReason());
        RefreshRejectedException newEx = assertThrows(RefreshRejectedException.class,
                () -> store.rotate("hash-new", "webapp", "x", "y", 0L, "z"));
        assertEquals(RefreshRejectReason.REVOKED, newEx.getReason());

        // 模拟进程重启：重新从文件加载，结论一致
        FileTokenStateStore restarted = newStore();
        assertEquals("REVOKED", restarted.tokenStatus(oldHash));
        assertEquals("REVOKED", restarted.tokenStatus("hash-new"));
        assertTrue(restarted.isAccessDenied("access-jti-1"));
        assertTrue(restarted.isAccessDenied("access-jti-2"));
        RefreshRejectedException afterRestart = assertThrows(RefreshRejectedException.class,
                () -> restarted.rotate("hash-new", "webapp", "x", "y", 0L, "z"));
        assertEquals(RefreshRejectReason.REVOKED, afterRestart.getReason());
    }

    @Test
    void expiredAndUnknownAndClientMismatchAreDistinguishable() {
        FileTokenStateStore store = newStore();
        String oldHash = "hash-expiry";
        // 已过期的家族
        store.createFamily("alice", "webapp", oldHash, "rjti",
                clock.instant().toEpochMilli() - 10L, "access-jti", List.of());

        RefreshRejectedException expired = assertThrows(RefreshRejectedException.class,
                () -> store.rotate(oldHash, "webapp", "x", "y", 1L, "z"));
        assertEquals(RefreshRejectReason.EXPIRED, expired.getReason());

        RefreshRejectedException notFound = assertThrows(RefreshRejectedException.class,
                () -> store.rotate("no-such-hash", "webapp", "x", "y", 1L, "z"));
        assertEquals(RefreshRejectReason.NOT_FOUND, notFound.getReason());

        String mismatchHash = "hash-client";
        createFamily(store, mismatchHash);
        RefreshRejectedException mismatch = assertThrows(RefreshRejectedException.class,
                () -> store.rotate(mismatchHash, "other-client", "x", "y", 1L, "z"));
        assertEquals(RefreshRejectReason.CLIENT_MISMATCH, mismatch.getReason());
    }

    static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration d) {
            instant = instant.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
