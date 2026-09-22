package com.github.highcumontoa.authaccesscontroljava.authz;

/**
 * 访问控制拒绝的可区分原因。
 */
public enum AccessRejectReason {
    MISSING_ROLE,
    INSUFFICIENT_SCOPE,
    RESOURCE_OWNER_MISMATCH
}
