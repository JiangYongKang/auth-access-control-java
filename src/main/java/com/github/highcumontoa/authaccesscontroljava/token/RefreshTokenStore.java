package com.github.highcumontoa.authaccesscontroljava.token;

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

    record StoredToken(String rawToken, String familyId, long generation) {
    }

    enum RotationOutcome { SUCCESS, UNKNOWN, CLIENT_MISMATCH, EXPIRED, REVOKED, REPLAYED }

    record RotationResult(RotationOutcome outcome, RefreshFamily family, StoredToken nextToken) {
    }

    enum FamilyStatus { ACTIVE_CURRENT, ACTIVE_STALE, REVOKED, UNKNOWN }
}
