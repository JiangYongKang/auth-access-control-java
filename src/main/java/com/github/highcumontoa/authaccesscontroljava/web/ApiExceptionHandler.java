package com.github.highcumontoa.authaccesscontroljava.web;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.github.highcumontoa.authaccesscontroljava.authz.AccessDeniedException;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshRejectedException;
import com.github.highcumontoa.authaccesscontroljava.token.TokenValidationException;

/**
 * 统一错误响应：不同拒绝原因以 reason / error 字段区分，结论可解释、可复现。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(TokenValidationException.class)
    public ResponseEntity<Map<String, Object>> handleToken(TokenValidationException ex) {
        return build(HttpStatus.UNAUTHORIZED, "invalid_token", ex.getReason().name());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccess(AccessDeniedException ex) {
        return build(HttpStatus.FORBIDDEN, "access_denied", ex.getReason().name());
    }

    @ExceptionHandler(RefreshRejectedException.class)
    public ResponseEntity<Map<String, Object>> handleRefresh(RefreshRejectedException ex) {
        return build(HttpStatus.BAD_REQUEST, "invalid_grant", ex.getReason().name());
    }

    @ExceptionHandler(RefreshOAuthException.class)
    public ResponseEntity<Map<String, Object>> handleRefreshOAuth(RefreshOAuthException ex) {
        return build(HttpStatus.BAD_REQUEST, ex.getError(), ex.getReason());
    }

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<Map<String, Object>> handleOAuth(OAuthException ex) {
        HttpStatus status = "invalid_client".equals(ex.getError())
                || "invalid_grant".equals(ex.getError())
                ? HttpStatus.UNAUTHORIZED : HttpStatus.BAD_REQUEST;
        return build(status, ex.getError(), ex.getError().toUpperCase());
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, String error, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("reason", reason);
        return ResponseEntity.status(status).body(body);
    }
}
