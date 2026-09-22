package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.security.RateLimitService;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class RateLimitServiceTest {

    static class FixedClock extends Clock {
        private volatile long seconds = 1_000L;

        void set(long seconds) {
            this.seconds = seconds;
        }

        @Override
        public Instant now() {
            return Instant.ofEpochSecond(seconds);
        }
    }

    private RateLimitService service(int max, long window, FixedClock clock) {
        AuthProperties props = new AuthProperties();
        props.getRatelimit().setMaxRequests(max);
        props.getRatelimit().setWindowSeconds(window);
        return new RateLimitService(props, clock);
    }

    @Test
    void allowsExactlyMaxThenRejectsWithinWindow() {
        FixedClock clock = new FixedClock();
        RateLimitService limiter = service(3, 60, clock);

        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isFalse();
        assertThat(limiter.tryAcquire("alice")).isFalse();
    }

    @Test
    void differentSubjectsHaveIndependentWindows() {
        FixedClock clock = new FixedClock();
        RateLimitService limiter = service(1, 60, clock);

        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("bob")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isFalse();
        assertThat(limiter.tryAcquire("bob")).isFalse();
    }

    @Test
    void windowRollsOverAndBudgetResets() {
        FixedClock clock = new FixedClock();
        RateLimitService limiter = service(2, 10, clock);

        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isFalse();

        clock.set(1_010L);
        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isTrue();
        assertThat(limiter.tryAcquire("alice")).isFalse();
    }

    @Test
    void concurrencyNeverLetsMoreThanMaxThrough() throws Exception {
        FixedClock clock = new FixedClock();
        RateLimitService limiter = service(100, 60, clock);
        int threads = 500;
        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (limiter.tryAcquire("hot-subject")) {
                        allowed.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        // 关键断言：高并发下允许通过的数量必须恰好等于上限，一个不多
        assertThat(allowed.get()).isEqualTo(100);
    }
}
