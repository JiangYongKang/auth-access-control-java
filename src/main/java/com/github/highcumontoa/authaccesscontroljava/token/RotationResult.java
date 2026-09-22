package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 刷新轮换结果：包含新令牌对以及旧令牌的判定状态。
 *
 * @param tokens    新令牌对
 * @param oldStatus 旧刷新令牌当前状态（ACTIVE / ROTATED / REVOKED）
 * @param replayed  旧令牌是否为重放（ROTATED 之后再次使用且超出并发宽限窗口）
 */
public record RotationResult(IssuedTokenSet tokens, String oldStatus, boolean replayed) {
}
