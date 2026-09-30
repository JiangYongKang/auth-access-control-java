package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason;
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

    /** 列出某主体名下的全部族（含已注销/已过期），按建立时间升序。 */
    List<RefreshFamily> listBySubject(String subject);

    /** 定向注销单个会话（族）。返回该族是否存在且此前处于有效状态。 */
    boolean logoutSession(String familyId, SessionLogoutReason reason);

    /** 注销某主体名下当前所有有效会话，返回被注销的会话数。 */
    int logoutAllBySubject(String subject, SessionLogoutReason reason);

    /** 记录一次会话使用（更新 lastUsedAt）；允许合并/节流落盘，不影响任何校验结论。 */
    void touch(String familyId, long epochSeconds);

    record StoredToken(String rawToken, String familyId, long generation) {
    }

    enum RotationOutcome { SUCCESS, UNKNOWN, CLIENT_MISMATCH, EXPIRED, REVOKED, REPLAYED }

    record RotationResult(RotationOutcome outcome, RefreshFamily family, StoredToken nextToken) {
    }

    enum FamilyStatus { ACTIVE_CURRENT, ACTIVE_STALE, REVOKED, LOGGED_OUT, UNKNOWN }
}
