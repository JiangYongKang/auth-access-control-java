package com.github.highcumontoa.authaccesscontroljava.web;

/**
 * 刷新/撤销失败：携带可区分的 RefreshRejectReason。
 */
public class RefreshOAuthException extends OAuthException {

    public RefreshOAuthException(String reason) {
        super("invalid_grant");
        this.reason = reason;
    }

    private final String reason;

    public String getReason() {
        return reason;
    }
}
