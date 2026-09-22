package com.github.highcumontoa.authaccesscontroljava.web;

/**
 * 令牌端点（/oauth/token）的 OAuth2 风格错误。
 */
public class OAuthException extends RuntimeException {

    private final String error;

    public OAuthException(String error) {
        super(error);
        this.error = error;
    }

    public String getError() {
        return error;
    }
}
