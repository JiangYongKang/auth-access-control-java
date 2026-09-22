package com.github.highcumontoa.authaccesscontroljava.authz;

/**
 * 权限/作用域/资源归属校验失败。
 */
public class AccessDeniedException extends RuntimeException {

    private final transient AccessRejectReason reason;

    public AccessDeniedException(AccessRejectReason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public AccessRejectReason getReason() {
        return reason;
    }
}
