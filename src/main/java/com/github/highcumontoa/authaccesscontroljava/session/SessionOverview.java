package com.github.highcumontoa.authaccesscontroljava.session;

/**
 * 会话概览（面向"按用户查看会话"的只读视图）。
 *
 * <p>故意不包含任何令牌原文：{@code sessionId} 即刷新令牌族 ID（非秘密，可用于定向注销）。
 *
 * @param sessionId  会话 ID（= 刷新令牌族 ID）
 * @param subject    会话主体（用户 ID）
 * @param clientId   发起登录的客户端
 * @param createdAt  会话建立时间（epoch 秒）
 * @param lastUsedAt 最近一次该会话访问令牌被使用的时间（epoch 秒）
 * @param expiresAt  会话（刷新族）过期时间（epoch 秒）
 */
public record SessionOverview(String sessionId, String subject, String clientId,
                              long createdAt, long lastUsedAt, long expiresAt) {
}
