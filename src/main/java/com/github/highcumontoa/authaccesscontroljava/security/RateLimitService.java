package com.github.highcumontoa.authaccesscontroljava.security;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 主体维度的固定时间窗口限流器。
 *
 * <p>每个主体维护 {@code (窗口起点, 已放行计数)}。{@link #tryAcquire(String)} 在同一把锁上完成
 * "窗口翻转判定 + 计数自增"，因此高并发下计数不会丢失，也绝不会放行超过 maxRequests 个请求。
 */
@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);

    private final int maxRequests;
    private final long windowSeconds;
    private final Clock clock;
    private final Map<String, Window> windows = new HashMap<>();

    public RateLimitService(AuthProperties props, Clock clock) {
        this.maxRequests = props.getRatelimit().getMaxRequests();
        this.windowSeconds = props.getRatelimit().getWindowSeconds();
        this.clock = clock;
    }

    public synchronized boolean tryAcquire(String subject) {
        long now = clock.epochSeconds();
        Window window = windows.get(subject);
        if (window == null || now >= window.start + windowSeconds) {
            window = new Window(now, 0);
            windows.put(subject, window);
        }
        if (window.count >= maxRequests) {
            long retryAfter = window.start + windowSeconds - now;
            log.info("Rate limit exceeded for subject={}, windowStart={}, count={}, retryAfter={}s",
                    subject, window.start, window.count, Math.max(1, retryAfter));
            return false;
        }
        window.count++;
        return true;
    }

    /** 测试辅助：清空全部窗口。 */
    public synchronized void reset() {
        windows.clear();
    }

    public int maxRequests() {
        return maxRequests;
    }

    public long windowSeconds() {
        return windowSeconds;
    }

    private static final class Window {
        private final long start;
        private int count;

        private Window(long start, int count) {
            this.start = start;
            this.count = count;
        }
    }
}
