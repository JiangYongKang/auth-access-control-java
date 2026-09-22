package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 访问令牌被拒绝的可区分原因。
 */
public enum TokenRejectReason {
    MISSING_AUTHORIZATION,
    MALFORMED,
    SIGNATURE_INVALID,
    EXPIRED,
    ISSUER_MISMATCH,
    AUDIENCE_MISMATCH,
    MISSING_REQUIRED_CLAIM,
    TOKEN_DENIED
}
