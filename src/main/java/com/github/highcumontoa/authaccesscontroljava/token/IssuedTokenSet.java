package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 一次签发（密码授权或刷新轮换）产生的令牌对。
 */
public record IssuedTokenSet(String accessToken, String refreshToken, String tokenType, long expiresIn,
                             String jti, String refreshJti) {
}
