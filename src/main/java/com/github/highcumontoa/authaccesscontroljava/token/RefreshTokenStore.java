package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenStore {

    /** 原子地消费刷新令牌：仅当哈希匹配且族有效时成功，调用后旧令牌立即失效。 */
    RotationResult consume(String rawRefreshToken, String clientId);

    /** 为新的授权创建族并返回原始刷新令牌（仅此一次可见原文）。 */
    StoredToken create(String subject, String clientId, long ttlSeconds,
                        java.util.List<String> roles, java.util.List<String> scopes);

    /** 撤销族（起因按显式令牌撤销处理）。 */
    default void revoke(String familyId, String reason) {
        revoke(familyId, reason, RevocationCause.TOKEN_REVOCATION);
    }

    /**
     * 原子地撤销族，并明确记录撤销的起因类别（显式令牌撤销 / 会话注销）。
     * 重复撤销同一族不会覆盖第一次记录的起因类别。
     */
    void revoke(String familyId, String reason, RevocationCause cause);

    Optional<RefreshFamily> findByFamilyId(String familyId);

    /** 访问令牌校验时查询族代际状态。 */
    FamilyStatus familyStatus(String familyId, long generation);

    /**
     * 一次性查询族的代际状态与撤销起因：相比先 {@link #familyStatus} 再 {@link #findByFamilyId}
     * 两次加锁查询，这里在同一把锁内返回一致快照，供自检/认证区分
     * 「令牌被撤销」与「会话被注销」。
     */
    FamilyRevocation familyRevocation(String familyId, long generation);

    /**
     * 原子地「校验归属与状态 → 撤销单个会话」，保证并发/重复注销同一会话时全进程恰好一次成功：
     * 只有第一次返回 {@link SessionRevokeOutcome#REVOKED}，其余返回 NOT_FOUND / ALREADY_REVOKED。
     * 整个检查—变更—落盘在实现的同一把锁内完成。
     *
     * @param subject 发起注销的主体；族不属于该主体时按 NOT_FOUND 处理，不泄露会话归属
     * @param nowEpochSeconds 当前时间（秒），用于判定会话是否已过期
     */
    SessionRevokeOutcome revokeSessionAtomically(String familyId, String subject,
                                                 String reason, long nowEpochSeconds);

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

    /** 族代际状态 + 若已撤销则带上撤销起因类别（快照）。 */
    record FamilyRevocation(FamilyStatus status, RevocationCause cause) {
        static FamilyRevocation of(FamilyStatus status) {
            return new FamilyRevocation(status, null);
        }
    }

    /** 原子注销单个会话的结果。 */
    enum SessionRevokeOutcome {
        /** 本次调用真正完成了注销（全进程至多一个线程得到）。 */
        REVOKED,
        /** 会话不存在（族未知，或不属于发起主体——不区分以避免泄露归属）。 */
        NOT_FOUND,
        /** 会话存在但此前已被注销（含并发重复注销中的落败者）。 */
        ALREADY_REVOKED,
        /** 会话已自然过期。 */
        EXPIRED
    }
}
