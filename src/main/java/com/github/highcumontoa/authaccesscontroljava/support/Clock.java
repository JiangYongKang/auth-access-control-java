package com.github.highcumontoa.authaccesscontroljava.support;

import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * 可替换的时钟：生产环境取系统时间；测试可注入固定/可推进时钟，
 * 使令牌过期等结论无需依赖真实睡眠即可确定复现。
 */
@Component
public class Clock {

    public Instant now() {
        return Instant.now();
    }

    public long epochSeconds() {
        return now().getEpochSecond();
    }
}
