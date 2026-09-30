package com.github.highcumontoa.authaccesscontroljava.session;

/**
 * 单个有效会话的对外概览。刻意不包含访问/刷新令牌原文，只保留可用于辨识与管理的元数据。
 *
 * @param sessionId 会话 ID（即刷新令牌族 ID，非秘密，可用于定向注销）
 * @param subject   会话主体（用户 ID 或 client:xxx）
 * @param clientId  建立该会话的客户端
 * @param createdAt 会话建立时间（epoch 秒）
 * @param lastUsedAt 最近使用时间（epoch 秒，秒级粒度的概览值）
 * @param expiresAt 会话（刷新族）到期时间（epoch 秒）
 */
public record SessionOverview(String sessionId, String subject, String clientId,
                              long createdAt, long lastUsedAt, long expiresAt) {
}
