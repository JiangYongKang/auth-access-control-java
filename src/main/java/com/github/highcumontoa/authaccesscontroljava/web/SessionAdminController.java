package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.security.AuthFilter;
import com.github.highcumontoa.authaccesscontroljava.security.RequireRole;
import com.github.highcumontoa.authaccesscontroljava.security.RequireScope;
import com.github.highcumontoa.authaccesscontroljava.session.SessionOverview;
import com.github.highcumontoa.authaccesscontroljava.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 会话管理端点（仅 ADMIN + read/write 作用域，供内网网关后的运维侧调用）：
 * <ul>
 *   <li>{@code GET  /api/admin/sessions/{userId}}        列出某用户当前有效会话概览；</li>
 *   <li>{@code POST /api/admin/sessions/{userId}/{sessionId}}  定向注销单个会话；</li>
 *   <li>{@code POST /api/admin/sessions/{userId}}        注销该用户名下全部会话。</li>
 * </ul>
 * 概览不暴露任何令牌原文；注销底层为撤销族，已发出的访问令牌立即失效。
 */
@RestController
public class SessionAdminController {

    private final SessionService sessionService;

    public SessionAdminController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping("/api/admin/sessions/{userId}")
    @RequireRole("ADMIN")
    @RequireScope("read")
    public Map<String, Object> list(@PathVariable String userId) {
        List<SessionOverview> sessions = sessionService.listSessions(userId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", userId);
        body.put("count", sessions.size());
        body.put("sessions", sessions);
        return body;
    }

    @PostMapping("/api/admin/sessions/{userId}/{sessionId}")
    @RequireRole("ADMIN")
    @RequireScope("write")
    public Map<String, Object> revokeOne(@PathVariable String userId,
                                         @PathVariable String sessionId) {
        sessionService.revokeSession(userId, sessionId);
        return Map.of("status", "revoked", "sessionId", sessionId);
    }

    @PostMapping("/api/admin/sessions/{userId}")
    @RequireRole("ADMIN")
    @RequireScope("write")
    public Map<String, Object> revokeAll(@PathVariable String userId,
                                         HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        int count = sessionService.revokeAllSessions(userId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "revoked");
        body.put("subject", userId);
        body.put("revoked", count);
        body.put("revokedBy", principal.subject());
        return body;
    }
}
