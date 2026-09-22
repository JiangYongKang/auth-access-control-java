package com.github.highcumontoa.authaccesscontroljava.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 认证与访问控制的全部本地配置。
 * 签名密钥只以 Base64 形式存在于配置（可被环境变量 AUTH_TOKEN_KEY_BASE64 覆盖），
 * 明文密钥不会写入任何配置文件。
 */
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private final Token token = new Token();
    private final Refresh refresh = new Refresh();
    private final RateLimit rateLimit = new RateLimit();
    private List<UserConfig> users = new ArrayList<>();
    private List<ClientConfig> clients = new ArrayList<>();
    /** key: 资源(文档)id, value: 归属用户名 */
    private Map<String, String> documents = new LinkedHashMap<>();

    public Token getToken() {
        return token;
    }

    public Refresh getRefresh() {
        return refresh;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public List<UserConfig> getUsers() {
        return users;
    }

    public void setUsers(List<UserConfig> users) {
        this.users = users;
    }

    public List<ClientConfig> getClients() {
        return clients;
    }

    public void setClients(List<ClientConfig> clients) {
        this.clients = clients;
    }

    public Map<String, String> getDocuments() {
        return documents;
    }

    public void setDocuments(Map<String, String> documents) {
        this.documents = documents;
    }

    public static class Token {
        /** HMAC-SHA256 密钥的 Base64 编码（非明文） */
        private String keyBase64;
        private String issuer = "local-auth";
        private String audience = "local-api";
        private Duration ttl = Duration.ofMinutes(30);

        public String getKeyBase64() {
            return keyBase64;
        }

        public void setKeyBase64(String keyBase64) {
            this.keyBase64 = keyBase64;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }
    }

    public static class Refresh {
        private Duration ttl = Duration.ofDays(7);
        private Duration graceWindow = Duration.ofMillis(100);
        /** 持久化文件（进程重启后撤销/重放结论保持一致） */
        private String storePath = "data/token-state.json";

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }

        public Duration getGraceWindow() {
            return graceWindow;
        }

        public void setGraceWindow(Duration graceWindow) {
            this.graceWindow = graceWindow;
        }

        public String getStorePath() {
            return storePath;
        }

        public void setStorePath(String storePath) {
            this.storePath = storePath;
        }
    }

    public static class RateLimit {
        private int windowRequests = 100;
        private Duration window = Duration.ofMinutes(1);

        public int getWindowRequests() {
            return windowRequests;
        }

        public void setWindowRequests(int windowRequests) {
            this.windowRequests = windowRequests;
        }

        public Duration getWindow() {
            return window;
        }

        public void setWindow(Duration window) {
            this.window = window;
        }
    }

    public static class UserConfig {
        private String username;
        /** PBKDF2 哈希字符串，密码不明文落盘 */
        private String passwordHash;
        private List<String> roles = new ArrayList<>();

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPasswordHash() {
            return passwordHash;
        }

        public void setPasswordHash(String passwordHash) {
            this.passwordHash = passwordHash;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
    }

    public static class ClientConfig {
        private String clientId;
        /** 客户端密钥的 PBKDF2 哈希 */
        private String secretHash;
        private List<String> scopes = new ArrayList<>();

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getSecretHash() {
            return secretHash;
        }

        public void setSecretHash(String secretHash) {
            this.secretHash = secretHash;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }
}
