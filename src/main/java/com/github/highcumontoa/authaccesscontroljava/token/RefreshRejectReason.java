package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 刷新令牌使用/撤销被拒绝的可区分原因。
 */
public enum RefreshRejectReason {
    NOT_FOUND,
    EXPIRED,
    REVOKED,
    REPLAYED,
    CONCURRENT_REUSE,
    CLIENT_MISMATCH
}
