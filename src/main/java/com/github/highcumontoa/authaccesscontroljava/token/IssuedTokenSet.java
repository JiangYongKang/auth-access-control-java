package com.github.highcumontoa.authaccesscontroljava.token;

public record IssuedTokenSet(String accessToken, String refreshToken, String tokenType,
                            long expiresIn, String familyId) {
}
