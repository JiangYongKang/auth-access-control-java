package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.domain.AccountDirectory;
import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.security.AuthFilter;
import com.github.highcumontoa.authaccesscontroljava.security.RequireRole;
import com.github.highcumontoa.authaccesscontroljava.security.RequireScope;
import com.github.highcumontoa.authaccesscontroljava.security.SubjectScoped;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * 演示用受保护资源，覆盖三类访问控制：
 * <ul>
 *   <li>{@code /api/profile/{userId}} —— 作用域 + 主体一致（签发主体与请求资源不符则拒绝）；</li>
 *   <li>{@code /api/admin/users} —— 角色（ADMIN）；</li>
 *   <li>{@code /api/resources/{resourceId}} —— 作用域 + 资源归属；</li>
 *   <li>{@code /api/ping} —— 仅认证 + 限流。</li>
 * </ul>
 */
@RestController
public class DemoResourceController {

    private final AccountDirectory accountDirectory;

    public DemoResourceController(AccountDirectory accountDirectory) {
        this.accountDirectory = accountDirectory;
    }

    @GetMapping("/api/profile/{userId}")
    @RequireScope("read")
    @SubjectScoped(pathVariable = "userId")
    public Map<String, Object> profile(@PathVariable String userId, HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        var user = accountDirectory.findUserById(userId).orElseThrow();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", user.id());
        body.put("username", user.username());
        body.put("roles", user.roles());
        body.put("requestedBy", principal.subject());
        return body;
    }

    @GetMapping("/api/admin/users")
    @RequireRole("ADMIN")
    @RequireScope("read")
    public Map<String, Object> adminUsers(HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        return Map.of(
                "users", new String[]{"u-alice", "u-bob", "u-admin"},
                "requestedBy", principal.subject());
    }

    @GetMapping("/api/resources/{resourceId}")
    @RequireScope("read")
    @SubjectScoped(pathVariable = "resourceId")
    public Map<String, Object> resource(@PathVariable String resourceId, HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        var resource = accountDirectory.findResource(resourceId).orElseThrow();
        return Map.of(
                "resourceId", resource.id(),
                "name", resource.name(),
                "owner", resource.ownerUserId(),
                "requestedBy", principal.subject());
    }

    @GetMapping("/api/ping")
    public Map<String, Object> ping(HttpServletRequest request) {
        CurrentPrincipal principal = AuthFilter.principal(request);
        return Map.of("pong", true, "subject", principal.subject());
    }
}
