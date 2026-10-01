package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenStore {

    /** 原子地消费刷新令牌：仅当哈希匹配且族有效时成功，调用后旧令牌立即失效。 */
    RotationResult consume(String rawRefreshToken, String clientId);

    /** 为新的授权创建族并返回原始刷新令牌（仅此一次可见原文）。 */
    StoredToken create(String subject, String clientId, long ttlSeconds,
                        java.util.List<String> roles, java.util.List<String> scopes);

    /**
     * 撤销族（令牌端点显式撤销，起因记为 {@link RevocationCause#TOKEN_REVOCATION}）。
     * 幂等：族不存在或已撤销时不做任何事，也不改写既有撤销起因。
     */
    void revoke(String familyId, String reason);

    /**
     * 原子地「检查—注销」单个会话：仅当族存在、属于 {@code subject}、未撤销且未过期时，
     * 才在同一把锁内完成撤销（起因记为 {@link RevocationCause#SESSION_LOGOUT}）。
     *
     * <p>因此并发或重复注销同一会话时，全进程<b>恰好一次</b>返回 true；
     * 其余调用（会话不存在 / 不属于该主体 / 已注销 / 已过期）返回 false。
     *
     * @return true 仅当本次调用真正执行了注销
     */
    boolean revokeSession(String familyId, String subject, String reason);

    /**
     * 查询族的撤销起因；族不存在或未撤销时返回 null。
     * 历史落盘记录缺少起因字段时，实现按 {@link RevocationCause#TOKEN_REVOCATION} 解释。
     */
    RevocationCause revocationCause(String familyId);

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

    /**
     * 族被撤销的起因，持久化在族记录上，自检据此把「令牌本身被撤销」与
     * 「会话被踢下线导致令牌失效」明确区分为两种无效原因。
     */
    enum RevocationCause {
        /** 令牌端点显式撤销（RFC 7009 /oauth/revoke）。 */
        TOKEN_REVOCATION,
        /** 会话管理端点注销会话（踢下线）。 */
        SESSION_LOGOUT
    }
}
