package com.github.highcumontoa.authaccesscontroljava.session;

import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshFamily;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 用户会话管理：按主体列出有效会话、定向注销单个会话、一次性注销全部会话。
 *
 * <p>会话与刷新令牌族一一对应（familyId 即 sessionId）。同一用户用不同客户端分别登录
 * 会产生互不影响的多个会话；定向注销只作用于目标会话，注销后该会话已签发的访问令牌立即失效。
 * 所有状态由 {@link RefreshTokenStore} 持久化，进程重启后结论保持一致。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final RefreshTokenStore store;
    private final Clock clock;

    public SessionService(RefreshTokenStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** 列出主体名下当前仍有效的会话概览（不含令牌原文）；已注销/已过期的不返回。 */
    public List<SessionOverview> listActiveSessions(String subject) {
        long now = clock.epochSeconds();
        List<SessionOverview> result = new ArrayList<>();
        for (RefreshFamily family : store.listBySubject(subject)) {
            if (!family.isRevoked() && !family.isExpiredAt(now)) {
                result.add(toOverview(family));
            }
        }
        return result;
    }

    /**
     * 定向注销单个会话。
     *
     * @param callerSubject 调用方主体（路径中的 userId）
     * @param isAdmin       调用方是否具备 ADMIN（管理员可管理任意用户的会话）
     * @throws RejectException FORBIDDEN_OWNER 会话不属于该用户；SESSION_NOT_FOUND 会话不存在或已失效
     */
    public void logoutSession(String callerSubject, String sessionId, boolean isAdmin) {
        RefreshFamily family = store.findByFamilyId(sessionId).orElseThrow(
                () -> new RejectException(RejectReason.SESSION_NOT_FOUND,
                        "session does not exist or is no longer active: " + sessionId));
        if (!isAdmin && !callerSubject.equals(family.getSubject())) {
            log.info("Session logout denied: caller={} does not own session={} owner={}",
                    callerSubject, sessionId, family.getSubject());
            throw new RejectException(RejectReason.FORBIDDEN_OWNER,
                    "session is owned by another subject");
        }
        long now = clock.epochSeconds();
        if (family.isRevoked() || family.isExpiredAt(now)) {
            throw new RejectException(RejectReason.SESSION_NOT_FOUND,
                    "session does not exist or is no longer active: " + sessionId);
        }
        boolean changed = store.logoutSession(sessionId, SessionLogoutReason.SESSION_REVOKED);
        if (!changed) {
            // 并发兜底：另一线程刚注销了同一会话。
            throw new RejectException(RejectReason.SESSION_NOT_FOUND,
                    "session does not exist or is no longer active: " + sessionId);
        }
        log.info("Session revoked: session={}, subject={}, by={}",
                sessionId, family.getSubject(), callerSubject);
    }

    /** 注销主体名下所有当前有效会话，返回注销数量（其它会话不受影响）。 */
    public int logoutAll(String subject) {
        return store.logoutAllBySubject(subject, SessionLogoutReason.ALL_SESSIONS_REVOKED);
    }

    private static SessionOverview toOverview(RefreshFamily family) {
        return new SessionOverview(
                family.getFamilyId(),
                family.getSubject(),
                family.getClientId(),
                family.getIssuedAt(),
                family.getLastUsedAt() <= 0 ? family.getIssuedAt() : family.getLastUsedAt(),
                family.getExpiresAt());
    }
}
