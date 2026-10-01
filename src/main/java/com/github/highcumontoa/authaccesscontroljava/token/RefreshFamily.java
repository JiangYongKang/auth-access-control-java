package com.github.highcumontoa.authaccesscontroljava.token;

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
    /**
     * 撤销的起因类别（显式令牌撤销 vs 会话注销），与 revoked 同时落盘。
     * 旧版本写出的状态文件没有该字段，读取后为 null，由 {@link #effectiveRevocationCause()}
     * 依据 revokeReason 兜底分类，保证升级后结论不退化。
     */
    private RevocationCause revocationCause;
    private List<String> roles;
    private List<String> scopes;
    /**
     * 最近一次「使用」该会话的大致时间（访问令牌通过认证 / 刷新）。
     * 仅为会话概览而记录，不参与任何安全判定；持久化为秒级时间戳，不落任何令牌原文。
     */
    private long lastUsedAt;

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

    public RevocationCause getRevocationCause() { return revocationCause; }
    public void setRevocationCause(RevocationCause revocationCause) { this.revocationCause = revocationCause; }

    /**
     * 已撤销族的起因类别。新状态始终显式带类别；旧版本状态文件该字段缺失（null）时，
     * 依据历史 revokeReason 文本兜底识别会话注销，识别不出的一律按显式令牌撤销处理
     * （保守归类，避免把撤销误报成会话注销）。
     */
    public RevocationCause effectiveRevocationCause() {
        if (revocationCause != null) {
            return revocationCause;
        }
        if (revokeReason != null && revokeReason.contains("session")) {
            return RevocationCause.SESSION_LOGOUT;
        }
        return RevocationCause.TOKEN_REVOCATION;
    }

    public List<String> getRoles() { return roles == null ? List.of() : roles; }
    public void setRoles(List<String> roles) { this.roles = roles; }

    public List<String> getScopes() { return scopes == null ? List.of() : scopes; }
    public void setScopes(List<String> scopes) { this.scopes = scopes; }

    public long getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(long lastUsedAt) { this.lastUsedAt = lastUsedAt; }
}
