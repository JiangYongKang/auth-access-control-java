package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;

public record AccessTokenClaims(String iss, String sub, String aud, String jti,
                                String clientId, String fam, long iat, long exp, long gen,
                                List<String> roles, List<String> scopes) {
}
