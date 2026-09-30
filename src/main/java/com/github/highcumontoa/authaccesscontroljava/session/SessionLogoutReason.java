package com.github.highcumontoa.authaccesscontroljava.session;

/**
 * 会话结束原因。持久化在族状态中，使"显式撤销族"与"定向/批量注销会话"在校验与自检时可区分。
 */
public enum SessionLogoutReason {

    /** 族仍有效（未注销/未撤销）。 */
    NONE,
    /** 注销了单个会话（不牵连同主体的其它会话）。 */
    SESSION_REVOKED,
    /** 一次性注销该主体名下全部会话。 */
    ALL_SESSIONS_REVOKED,
    /** RFC 7009 风格的令牌/族撤销。 */
    TOKEN_REVOKED
}
