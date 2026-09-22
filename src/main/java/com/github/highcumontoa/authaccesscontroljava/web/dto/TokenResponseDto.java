package com.github.highcumontoa.authaccesscontroljava.web.dto;

public class TokenResponseDto {
    private String access_token;
    private String refresh_token;
    private String token_type;
    private long expires_in;

    public TokenResponseDto() {
    }

    public TokenResponseDto(String accessToken, String refreshToken, String tokenType, long expiresIn) {
        this.access_token = accessToken;
        this.refresh_token = refreshToken;
        this.token_type = tokenType;
        this.expires_in = expiresIn;
    }

    public String getAccess_token() { return access_token; }
    public String getRefresh_token() { return refresh_token; }
    public String getToken_type() { return token_type; }
    public long getExpires_in() { return expires_in; }
}
