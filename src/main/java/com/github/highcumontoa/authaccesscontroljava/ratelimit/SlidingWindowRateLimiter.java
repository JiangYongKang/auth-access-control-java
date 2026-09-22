package com.github.highcumontoa.authaccesscontroljava.ratelimit;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;

/**
 * 每个 key 独立加锁的滑动日志窗口限流器。
 *
 * <p>“清理窗口外请求 → 计数 → 占用配额”在同一把 key 级锁内完成，
 * 因此即使高并发也不会有两个线程同时把计数从临界点推过配额，绝不放行超量请求。</p>
 */
@Component
public class SlidingWindowRateLimiter implements RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(SlidingWindowRateLimiter.class);

    private final AuthProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Deque<Long>> windows = new ConcurrentHashMap<>();

    public SlidingWindowRateLimiter(AuthProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public boolean tryAcquire(String key) {
        int limit = properties.getRateLimit().getWindowRequests();
        long windowMs = properties.getRateLimit().getWindow().toMillis();
        long now = clock.instant().toEpochMilli();
        long cutoff = now - windowMs;

        Object lock = locks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            Deque<Long> hits = windows.computeIfAbsent(key, k -> new ArrayDeque<>());
            while (!hits.isEmpty() && hits.peekFirst() <= cutoff) {
                hits.pollFirst();
            }
            if (hits.size() >= limit) {
                log.warn("限流触发: key={}, windowHits={}, limit={}", key, hits.size(), limit);
                return false;
            }
            hits.addLast(now);
            return true;
        }
    }
}
