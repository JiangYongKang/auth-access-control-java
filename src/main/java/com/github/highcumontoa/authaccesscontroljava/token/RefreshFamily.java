package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason;
import java.util.List;

/**
 * 刷新令牌族：一次授权（密码登录 / 客户端凭据）创建一个族，之后整条刷新轮换链都属于该族。
 *
 * <p>语义：
 * <ul>
 *   <li>{@code generation} 从 0 起，每成功轮换一次加 1；访问令牌携带签发时的 gen，
 *       与族当前 gen 不一致即说明该访问令牌属于"旧轮换"，必须拒绝（TOKEN_FAMILY_STALE）。</li>
 *   <li>{@code currentTokenHash} 只保存当前有效刷新令牌原文的 SHA-256，旧哈希直接覆盖，
 *       因此同一刷新令牌无法被第二次使用。</li>
 *   <li>{@code revoked=true} 后，族内所有刷新令牌与历史访问令牌均不可再用（TOKEN_FAMILY_REVOKED）。</li>
 * </ul>
 * 本类会被 JSON 序列化落盘，故字段中不得出现任何明文密钥/令牌。
 */
public class RefreshFamily {

    private String familyId;
    private String subject;
    private String clientId;
    private long generation;
    private String currentTokenHash;
    private long issuedAt;
    private long expiresAt;
    private boolean revoked;
    private String revokeReason;
    private long lastUsedAt;
    private SessionLogoutReason logoutReason = SessionLogoutReason.NONE;
    private List<String> roles;
    private List<String> scopes;

    public RefreshFamily() {
    }

    public boolean isExpiredAt(long epochSeconds) {
        return expiresAt <= epochSeconds;
    }

    public String getFamilyId() { return familyId; }
    public void setFamilyId(String familyId) { this.familyId = familyId; }

    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public long getGeneration() { return generation; }
    public void setGeneration(long generation) { this.generation = generation; }

    public String getCurrentTokenHash() { return currentTokenHash; }
    public void setCurrentTokenHash(String currentTokenHash) { this.currentTokenHash = currentTokenHash; }

    public long getIssuedAt() { return issuedAt; }
    public void setIssuedAt(long issuedAt) { this.issuedAt = issuedAt; }

    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }

    public String getRevokeReason() { return revokeReason; }
    public void setRevokeReason(String revokeReason) { this.revokeReason = revokeReason; }

    public long getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(long lastUsedAt) { this.lastUsedAt = lastUsedAt; }

    public SessionLogoutReason getLogoutReason() {
        return logoutReason == null ? SessionLogoutReason.NONE : logoutReason;
    }
    public void setLogoutReason(SessionLogoutReason logoutReason) { this.logoutReason = logoutReason; }

    public List<String> getRoles() { return roles == null ? List.of() : roles; }
    public void setRoles(List<String> roles) { this.roles = roles; }

    public List<String> getScopes() { return scopes == null ? List.of() : scopes; }
    public void setScopes(List<String> scopes) { this.scopes = scopes; }
}
