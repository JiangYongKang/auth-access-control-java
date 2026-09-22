package com.github.highcumontoa.authaccesscontroljava.domain;

import java.util.List;

public record UserAccount(String id, String username, String passwordHash, List<String> roles) {
}
