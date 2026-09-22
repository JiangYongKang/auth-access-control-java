package com.github.highcumontoa.authaccesscontroljava.authz;

import java.util.List;

/**
 * 通过认证后放入请求上下文的当前主体。
 */
public record CurrentPrincipal(String subject, String clientId, List<String> roles, List<String> scopes,
                               String jti) {
}
