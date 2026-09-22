package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.ratelimit.SlidingWindowRateLimiter;

class SlidingWindowRateLimiterTest {

    private AuthProperties properties;
    private MutableClock clock;

    @BeforeEach
    void setUp() {
        properties = new AuthProperties();
        properties.getRateLimit().setWindowRequests(5);
        properties.getRateLimit().setWindow(Duration.ofSeconds(10));
        clock = new MutableClock(Instant.parse("2026-09-23T00:00:00Z"));
    }

    @Test
    void allowsExactlyLimitThenRejects() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(properties, clock);
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquire("user"), "第 " + (i + 1) + " 次应放行");
        }
        assertFalse(limiter.tryAcquire("user"), "第 6 次必须被限流");
        assertFalse(limiter.tryAcquire("user"), "第 7 次必须被限流");
    }

    @Test
    void windowSlidesAndAcceptsAgain() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(properties, clock);
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquire("user"));
        }
        assertFalse(limiter.tryAcquire("user"));
        clock.advance(Duration.ofSeconds(10).plusMillis(1));
        assertTrue(limiter.tryAcquire("user"), "窗口滑动后应重新放行");
    }

    @Test
    void keysAreIndependent() {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(properties, clock);
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquire("a"));
        }
        assertFalse(limiter.tryAcquire("a"));
        assertTrue(limiter.tryAcquire("b"), "不同主体独立计数");
    }

    @Test
    void concurrentRequestsNeverExceedLimit() throws Exception {
        SlidingWindowRateLimiter limiter = new SlidingWindowRateLimiter(properties, clock);
        int threads = 200;
        // 使用虚拟线程承载屏障等待，避免在平台线程受限环境下自死锁
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await();
                    if (limiter.tryAcquire("hot-user")) {
                        accepted.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(15, TimeUnit.SECONDS));
            start.countDown();
            for (Future<?> f : futures) {
                f.get(15, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(5, accepted.get(), "高并发下放行数必须恰好等于配额，不能超量");
        assertEquals(threads - 5, rejected.get());
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
