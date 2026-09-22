package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 刷新令牌家族状态与访问令牌拒绝清单的持久化存储。
 * 状态文件原子写入，进程重启后撤销/重放结论保持一致。
 */
public interface TokenStateStore {

    /**
     * 创建一个全新的刷新令牌家族并记录首个令牌。
     *
     * @param currentAccessJti 当前配套访问令牌的 jti（轮换/撤销时进入拒绝清单）
     * @param scopes           授权作用域（刷新后新访问令牌仍携带相同作用域）
     */
    TokenState createFamily(String subject, String clientId, String refreshHash, String refreshJti,
                            long expiresAtEpochMs, String currentAccessJti, java.util.List<String> scopes);

    /**
     * 尝试把指定令牌在其家族内轮换：
     * 成功时原子地把旧令牌标记为 ROTATED、登记新令牌、把旧访问令牌 jti 加入拒绝清单、
     * 并记录新访问令牌 jti；旧令牌已撤销/已轮换时抛出 {@link RefreshRejectedException}。
     *
     * @param newAccessJti 本次轮换配套的新访问令牌 jti
     */
    RotationOutcome rotate(String refreshHash, String clientId, String newRefreshHash, String newRefreshJti,
                           long newExpiresAtEpochMs, String newAccessJti);

    /**
     * 撤销整个家族（登出）：撤销后家族内所有刷新令牌及当前访问令牌 jti 均被拒绝。
     * 返回是否实际执行了撤销。
     */
    boolean revokeFamily(String refreshHash, String clientId);

    /**
     * 家族是否处于撤销状态。
     */
    boolean isFamilyRevoked(String familyId);

    /**
     * 查询令牌状态（仅供测试/管理用途）：ACTIVE / ROTATED / REVOKED / UNKNOWN。
     */
    String tokenStatus(String refreshHash);

    /**
     * 访问令牌 jti 是否在拒绝清单中（轮换/撤销后旧访问令牌立即失效）。
     */
    boolean isAccessDenied(String jti);

    record TokenState(String familyId, String subject, String clientId) {
    }

    record RotationOutcome(String familyId, String subject, String clientId, String oldStatus,
                           boolean replayed, java.util.List<String> scopes) {
    }
}
