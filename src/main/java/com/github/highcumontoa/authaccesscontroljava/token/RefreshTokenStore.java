package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenStore {

    /** 原子地消费刷新令牌：仅当哈希匹配且族有效时成功，调用后旧令牌立即失效。 */
    RotationResult consume(String rawRefreshToken, String clientId);

    /** 为新的授权创建族并返回原始刷新令牌（仅此一次可见原文）。 */
    StoredToken create(String subject, String clientId, long ttlSeconds,
                        java.util.List<String> roles, java.util.List<String> scopes);

    /** 撤销族。 */
    void revoke(String familyId, String reason);

    Optional<RefreshFamily> findByFamilyId(String familyId);

    /** 访问令牌校验时查询族代际状态。 */
    FamilyStatus familyStatus(String familyId, long generation);

    /**
     * 记录某会话「最近使用时间」（仅用于会话概览展示，不参与安全判定）。
     * 实现可对落盘做节流，以避免每个 API 请求都写盘。
     */
    void touch(String familyId, long epochSeconds);

    /** 列出某主体当前「有效」的会话（未撤销、未过期）。 */
    List<RefreshFamily> listActiveSessions(String subject);

    /**
     * 注销某主体名下全部有效会话（撤销其全部有效族）。
     * @return 实际被注销的会话数量
     */
    int revokeSessionsBySubject(String subject, String reason);

    record StoredToken(String rawToken, String familyId, long generation) {
    }

    enum RotationOutcome { SUCCESS, UNKNOWN, CLIENT_MISMATCH, EXPIRED, REVOKED, REPLAYED }

    record RotationResult(RotationOutcome outcome, RefreshFamily family, StoredToken nextToken) {
    }

    enum FamilyStatus { ACTIVE_CURRENT, ACTIVE_STALE, REVOKED, UNKNOWN }
}
