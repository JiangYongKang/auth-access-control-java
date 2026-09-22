package com.github.highcumontoa.authaccesscontroljava.domain;

import java.util.Set;

public record CurrentPrincipal(String subject, String clientId, Set<String> roles,
                               Set<String> scopes, String jti, long generation) {
}
