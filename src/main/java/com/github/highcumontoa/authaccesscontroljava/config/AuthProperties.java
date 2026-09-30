package com.github.highcumontoa.authaccesscontroljava.config;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private Security security = new Security();
    private Token token = new Token();
    private Ratelimit ratelimit = new Ratelimit();

    public Security getSecurity() { return security; }
    public void setSecurity(Security security) { this.security = security; }
    public Token getToken() { return token; }
    public void setToken(Token token) { this.token = token; }
    public Ratelimit getRatelimit() { return ratelimit; }
    public void setRatelimit(Ratelimit ratelimit) { this.ratelimit = ratelimit; }

    public static class Security {
        // 兼容旧配置：单密钥模式（等价于 id 为 "default" 的唯一密钥，且为当前签发密钥）。
        private String hmacKey = null;
        private String issuer = "local-auth-service";
        /** 多密钥映射：keyId -> 密钥原文；仅用于验签的旧密钥也配置在这里。 */
        private Map<String, String> signingKeys = new LinkedHashMap<>();
        /** 当前用于签发的密钥 ID；必须存在于 signingKeys（或单密钥兼容模式下为 default）。 */
        private String activeKeyId = null;

        public String getHmacKey() { return hmacKey; }
        public void setHmacKey(String hmacKey) { this.hmacKey = hmacKey; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public Map<String, String> getSigningKeys() { return signingKeys; }
        public void setSigningKeys(Map<String, String> signingKeys) { this.signingKeys = signingKeys; }
        public String getActiveKeyId() { return activeKeyId; }
        public void setActiveKeyId(String activeKeyId) { this.activeKeyId = activeKeyId; }
    }

    public static class Token {
        private long accessTtlSeconds = 600;
        private long refreshTtlSeconds = 1209600;
        private String stateFile = "data/refresh-state.json";
        public long getAccessTtlSeconds() { return accessTtlSeconds; }
        public void setAccessTtlSeconds(long accessTtlSeconds) { this.accessTtlSeconds = accessTtlSeconds; }
        public long getRefreshTtlSeconds() { return refreshTtlSeconds; }
        public void setRefreshTtlSeconds(long refreshTtlSeconds) { this.refreshTtlSeconds = refreshTtlSeconds; }
        public String getStateFile() { return stateFile; }
        public void setStateFile(String stateFile) { this.stateFile = stateFile; }
    }

    public static class Ratelimit {
        private int maxRequests = 10;
        private long windowSeconds = 60;
        public int getMaxRequests() { return maxRequests; }
        public void setMaxRequests(int maxRequests) { this.maxRequests = maxRequests; }
        public Ratelimit windowSeconds(long windowSeconds) { this.windowSeconds = windowSeconds; return this; }
        public long getWindowSeconds() { return windowSeconds; }
        public void setWindowSeconds(long windowSeconds) { this.windowSeconds = windowSeconds; }
    }
}
