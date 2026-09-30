package com.github.highcumontoa.authaccesscontroljava.session;

import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshFamily;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 用户会话管理：会话与刷新令牌「族」一一对应——同一用户在不同客户端分别登录即为互不影响的
 * 不同会话。支持按主体列出会话概览、定向注销单个会话、一次性注销某主体全部会话。
 *
 * <p>注销底层即「撤销族」：一旦注销，该会话此前已签发的访问令牌立刻不再被接受
 * （族撤销在本地访问令牌校验链中判定）。会话与撤销状态由 {@link RefreshTokenStore} 持久化，
 * 进程重启后保持一致。
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

    /** 列出某主体当前有效会话（不暴露任何令牌原文）。 */
    public List<SessionOverview> listSessions(String subject) {
        return store.listActiveSessions(subject).stream()
                .map(SessionService::toOverview)
                .toList();
    }

    /**
     * 定向注销单个会话。仅当该会话存在且属于该主体时执行，避免跨主体注销。
     * 注销后该会话已发出的访问令牌立即失效；同主体的其它会话不受影响。
     */
    public void revokeSession(String subject, String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "sessionId is required");
        }
        RefreshFamily family = store.findByFamilyId(sessionId)
                .orElseThrow(() -> new RejectException(RejectReason.SESSION_NOT_FOUND,
                        "session does not exist: " + sessionId));
        if (!subject.equals(family.getSubject())) {
            // 不向调用方泄露其它主体会话的存在
            throw new RejectException(RejectReason.SESSION_NOT_FOUND,
                    "session does not exist: " + sessionId);
        }
        if (family.isRevoked()) {
            throw new RejectException(RejectReason.SESSION_NOT_FOUND,
                    "session has already been revoked: " + sessionId);
        }
        if (family.isExpiredAt(clock.epochSeconds())) {
            throw new RejectException(RejectReason.SESSION_NOT_FOUND,
                    "session has expired: " + sessionId);
        }
        store.revoke(sessionId, "admin_session_logout");
        log.info("Session revoked: sessionId={}, subject={}", sessionId, subject);
    }

    /** 注销某主体名下所有有效会话；返回被注销的会话数量。 */
    public int revokeAllSessions(String subject) {
        int count = store.revokeSessionsBySubject(subject, "admin_logout_all_sessions");
        log.info("Revoked all sessions for subject={}, count={}", subject, count);
        return count;
    }

    private static SessionOverview toOverview(RefreshFamily f) {
        return new SessionOverview(
                f.getFamilyId(),
                f.getSubject(),
                f.getClientId(),
                f.getIssuedAt(),
                f.getLastUsedAt(),
                f.getExpiresAt());
    }
}
