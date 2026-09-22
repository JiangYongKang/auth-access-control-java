package com.github.highcumontoa.authaccesscontroljava.token;

import org.springframework.http.HttpStatus;

/**
 * 所有可区分的拒绝原因。errorCode 出现在响应体，httpStatus 决定 HTTP 状态码。
 */
public enum RejectReason {

    // 访问令牌相关
    MISSING_TOKEN(HttpStatus.UNAUTHORIZED, "missing_token"),
    MALFORMED_TOKEN(HttpStatus.UNAUTHORIZED, "malformed_token"),
    UNSUPPORTED_ALG(HttpStatus.UNAUTHORIZED, "unsupported_alg"),
    BAD_SIGNATURE(HttpStatus.UNAUTHORIZED, "bad_signature"),
    MISSING_CLAIMS(HttpStatus.UNAUTHORIZED, "missing_claims"),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "token_expired"),
    TOKEN_ISSUER_MISMATCH(HttpStatus.UNAUTHORIZED, "token_issuer_mismatch"),
    TOKEN_SUBJECT_MISMATCH(HttpStatus.UNAUTHORIZED, "token_subject_mismatch"),
    TOKEN_FAMILY_REVOKED(HttpStatus.UNAUTHORIZED, "token_family_revoked"),
    TOKEN_FAMILY_STALE(HttpStatus.UNAUTHORIZED, "token_family_stale"),

    // 令牌端点：凭据/授权相关
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "invalid_request"),
    UNSUPPORTED_GRANT_TYPE(HttpStatus.BAD_REQUEST, "unsupported_grant_type"),
    INVALID_CLIENT(HttpStatus.UNAUTHORIZED, "invalid_client"),
    INVALID_GRANT(HttpStatus.BAD_REQUEST, "invalid_grant"),
    INVALID_SCOPE(HttpStatus.BAD_REQUEST, "invalid_scope"),

    // 刷新令牌轮换/撤销相关
    INVALID_GRANT_REVOKED(HttpStatus.BAD_REQUEST, "invalid_grant_revoked"),
    INVALID_GRANT_REPLAYED(HttpStatus.BAD_REQUEST, "invalid_grant_replayed"),
    INVALID_GRANT_EXPIRED(HttpStatus.BAD_REQUEST, "invalid_grant_expired"),
    INVALID_GRANT_CLIENT_MISMATCH(HttpStatus.BAD_REQUEST, "invalid_grant_client_mismatch"),

    // 访问控制相关
    FORBIDDEN_ROLE(HttpStatus.FORBIDDEN, "forbidden_role"),
    FORBIDDEN_SCOPE(HttpStatus.FORBIDDEN, "forbidden_scope"),
    FORBIDDEN_OWNER(HttpStatus.FORBIDDEN, "forbidden_owner"),

    // 限流
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "rate_limited");

    private final HttpStatus httpStatus;
    private final String errorCode;

    RejectReason(HttpStatus httpStatus, String errorCode) {
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }

    public String errorCode() {
        return errorCode;
    }
}
