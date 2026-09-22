package com.github.highcumontoa.authaccesscontroljava.ratelimit;

/**
 * 固定主体的时间窗口限流器。
 */
public interface RateLimiter {

    /**
     * 尝试占用一次配额；超出窗口配额时返回 false（高并发下也不会放行超量请求）。
     */
    boolean tryAcquire(String key);
}
