package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 族被撤销的「起因类别」，随族状态一起持久化，用于让上层把两种语义明确区分开：
 * <ul>
 *   <li>{@link #TOKEN_REVOCATION}：令牌本身被显式撤销（RFC 7009 /oauth/revoke）；</li>
 *   <li>{@link #SESSION_LOGOUT}：所属会话被定向/批量注销（会话管理端点）。</li>
 * </ul>
 * 二者最终都令族进入 revoked 状态，但网关需要按不同策略处置，因此必须分别记录、分别呈现。
 */
public enum RevocationCause {
    /** 令牌被显式撤销（/oauth/revoke）。 */
    TOKEN_REVOCATION,
    /** 会话被注销（管理员定向注销单个会话或注销全部会话）。 */
    SESSION_LOGOUT
}
