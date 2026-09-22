package com.github.highcumontoa.authaccesscontroljava.domain;

import java.util.List;

public record ClientApp(String clientId, String clientSecret, List<String> allowedScopes) {
}
