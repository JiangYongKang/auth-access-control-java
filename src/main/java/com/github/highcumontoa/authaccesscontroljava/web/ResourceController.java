package com.github.highcumontoa.authaccesscontroljava.web;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.highcumontoa.authaccesscontroljava.authz.AuthorizationService;
import com.github.highcumontoa.authaccesscontroljava.authz.CurrentPrincipal;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 受保护资源接口：
 * <ul>
 *   <li>GET /api/profile         任意已认证主体；需要 scope=profile:read</li>
 *   <li>GET /api/admin           需要角色 ADMIN 且 scope=admin:read</li>
 *   <li>GET /api/documents/{id}  需要 scope=doc:read 且资源归属于当前主体</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    private final AuthorizationService authorizationService;

    public ResourceController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        CurrentPrincipal principal = current(request);
        authorizationService.requireScopes(principal, Set.of("profile:read"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", principal.subject());
        body.put("client", principal.clientId());
        body.put("roles", principal.roles());
        return body;
    }

    @GetMapping("/admin")
    public Map<String, Object> admin(HttpServletRequest request) {
        CurrentPrincipal principal = current(request);
        authorizationService.requireRoles(principal, Set.of("ADMIN"));
        authorizationService.requireScopes(principal, Set.of("admin:read"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("subject", principal.subject());
        body.put("message", "admin area");
        return body;
    }

    @GetMapping("/documents/{id}")
    public Map<String, Object> document(@PathVariable String id, HttpServletRequest request) {
        CurrentPrincipal principal = current(request);
        authorizationService.requireScopes(principal, Set.of("doc:read"));
        authorizationService.requireResourceOwner(principal, id);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("owner", principal.subject());
        body.put("content", "secret-of-" + id);
        return body;
    }

    private CurrentPrincipal current(HttpServletRequest request) {
        return (CurrentPrincipal) request.getAttribute(AuthenticationFilter.PRINCIPAL_ATTRIBUTE);
    }
}
