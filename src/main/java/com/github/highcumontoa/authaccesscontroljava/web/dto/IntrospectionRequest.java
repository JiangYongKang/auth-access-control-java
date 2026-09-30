package com.github.highcumontoa.authaccesscontroljava.web.dto;

/** 令牌自检请求（RFC 7662 风格）：客户端凭据 + 待检令牌。 */
public class IntrospectionRequest {

    private String client_id;
    private String client_secret;
    private String token;

    public String getClient_id() { return client_id; }
    public void setClient_id(String client_id) { this.client_id = client_id; }
    public String getClient_secret() { return client_secret; }
    public void setClient_secret(String client_secret) { this.client_secret = client_secret; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}
