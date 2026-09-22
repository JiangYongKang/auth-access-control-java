package com.github.highcumontoa.authaccesscontroljava.security;

/**
 * 日志脱敏工具：打印判定依据时对令牌、口令等敏感字段做掩码。
 * 规则：保留前 4 个字符与长度信息，其余用 * 替代；null/短串统一显示为 ****。
 */
public final class SensitiveLog {

    private static final int KEEP_PREFIX = 4;
    private static final String FULL_MASK = "****";

    private SensitiveLog() {
    }

    public static String mask(String value) {
        if (value == null || value.length() <= KEEP_PREFIX) {
            return FULL_MASK;
        }
        return value.substring(0, KEEP_PREFIX) + "***(" + value.length() + " chars)";
    }
}
