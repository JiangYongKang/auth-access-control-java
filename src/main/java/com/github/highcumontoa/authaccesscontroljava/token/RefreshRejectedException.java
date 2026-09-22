package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 刷新令牌轮换/撤销被拒绝。
 */
public class RefreshRejectedException extends RuntimeException {

    private final RefreshRejectReason reason;

    public RefreshRejectedException(RefreshRejectReason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public RefreshRejectReason getReason() {
        return reason;
    }
}
