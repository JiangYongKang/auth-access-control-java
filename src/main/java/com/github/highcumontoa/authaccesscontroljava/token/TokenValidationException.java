package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 访问令牌校验失败。reason 用于区分拒绝原因。
 */
public class TokenValidationException extends RuntimeException {

    private final TokenRejectReason reason;

    public TokenValidationException(TokenRejectReason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public TokenValidationException(TokenRejectReason reason, Throwable cause) {
        super(reason.name(), cause);
        this.reason = reason;
    }

    public TokenRejectReason getReason() {
        return reason;
    }
}
