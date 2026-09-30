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
        private String hmacKey = null;
        private String issuer = "local-auth-service";
        /**
         * 多签名密钥配置（支持平滑轮换）：key 为密钥 ID（kid），value 为密钥原文。
         * 与 {@link #hmacKey} 互斥：配置了非空 keys 时走多密钥模式，hmacKey 必须为空。
         * 密钥只来自配置/环境变量，进程内不允许把任何密钥明文写入磁盘。
         */
        private Map<String, String> keys = new LinkedHashMap<>();
        /** 当前用于签发新令牌的密钥 ID；多密钥模式下必须指向 {@link #keys} 中的一个。 */
        private String activeKeyId = null;
        public String getHmacKey() { return hmacKey; }
        public void setHmacKey(String hmacKey) { this.hmacKey = hmacKey; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public Map<String, String> getKeys() { return keys; }
        public void setKeys(Map<String, String> keys) { this.keys = keys; }
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
