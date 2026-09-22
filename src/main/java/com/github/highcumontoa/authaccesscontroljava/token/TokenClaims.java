package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;

/**
 * 访问令牌的声明集合。
 */
public record TokenClaims(String jti, String subject, String clientId, String issuer, String audience,
                          List<String> roles, List<String> scopes, long issuedAt, long expiresAt) {
}
