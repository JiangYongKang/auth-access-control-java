package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.security.AuthFilter;
import com.github.highcumontoa.authaccesscontroljava.security.RequireScope;
import com.github.highcumontoa.authaccesscontroljava.security.SubjectScoped;
import com.github.highcumontoa.authaccesscontroljava.session.SessionOverview;
import com.github.highcumontoa.authaccesscontroljava.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * 用户会话管理端点（均挂在 /api/** 下，需通过认证与限流）：
 * <ul>
 *   <li>{@code GET    /api/sessions/{userId}}：列出该用户当前有效会话概览（不暴露令牌原文）；</li>
 *   <li>{@code DELETE /api/sessions/{userId}}：一次性注销该用户全部会话；</li>
 *   <li>{@code DELETE /api/sessions/{userId}/{sessionId}}：只注销指定的单个会话。</li>
 * </ul>
 * 用户只能管理自己名下的会话；ADMIN 经 {@link SubjectScoped} 豁免后可管理任意用户。
 * 这些端点不改变调用方自身的登录态（管理员/本人的其他会话不受影响）。
 */
@RestController
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping("/api/sessions/{userId}")
    @RequireScope("read")
    @SubjectScoped(pathVariable = "userId")
    public Map<String, Object> list(@PathVariable String userId) {
        List<SessionOverview> sessions = sessionService.listActiveSessions(userId);
        return Map.of("userId", userId, "activeCount", sessions.size(), "sessions", sessions);
    }

    @DeleteMapping("/api/sessions/{userId}/{sessionId}")
    @SubjectScoped(pathVariable = "userId")
    public Map<String, Object> logoutOne(@PathVariable String userId,
                                         @PathVariable String sessionId,
                                         HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        boolean isAdmin = principal.roles().contains("ADMIN");
        sessionService.logoutSession(userId, sessionId, isAdmin);
        return Map.of("status", "logged_out", "sessionId", sessionId);
    }

    @DeleteMapping("/api/sessions/{userId}")
    @SubjectScoped(pathVariable = "userId")
    public Map<String, Object> logoutAll(@PathVariable String userId) {
        int count = sessionService.logoutAll(userId);
        return Map.of("status", "logged_out", "revokedSessions", count);
    }
}
