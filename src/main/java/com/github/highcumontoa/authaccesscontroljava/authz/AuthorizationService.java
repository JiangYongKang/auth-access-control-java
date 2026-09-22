package com.github.highcumontoa.authaccesscontroljava.authz;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;

/**
 * 基于角色、作用域与资源归属的访问判定，三类拒绝原因可区分。
 */
@Component
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final AuthProperties properties;

    public AuthorizationService(AuthProperties properties) {
        this.properties = properties;
    }

    /**
     * 要求主体具备任一给定角色。
     */
    public void requireRoles(CurrentPrincipal principal, Set<String> roles) {
        if (principal == null) {
            throw new AccessDeniedException(AccessRejectReason.MISSING_ROLE);
        }
        boolean ok = principal.roles().stream().anyMatch(roles::contains);
        if (!ok) {
            log.warn("访问拒绝(缺少角色): sub={}, required={}, actual={}",
                    principal.subject(), roles, principal.roles());
            throw new AccessDeniedException(AccessRejectReason.MISSING_ROLE);
        }
    }

    /**
     * 要求令牌具备全部给定作用域。
     */
    public void requireScopes(CurrentPrincipal principal, Set<String> scopes) {
        if (principal == null || !principal.scopes().containsAll(scopes)) {
            log.warn("访问拒绝(作用域不足): sub={}, required={}, actual={}",
                    principal == null ? "-" : principal.subject(), scopes,
                    principal == null ? "[]" : principal.scopes());
            throw new AccessDeniedException(AccessRejectReason.INSUFFICIENT_SCOPE);
        }
    }

    /**
     * 要求资源存在且归属于当前主体（资源归属表来自本地配置）。
     */
    public void requireResourceOwner(CurrentPrincipal principal, String resourceId) {
        String owner = properties.getDocuments().get(resourceId);
        if (principal == null || owner == null || !owner.equals(principal.subject())) {
            log.warn("访问拒绝(资源归属不符): sub={}, resource={}, owner={}",
                    principal == null ? "-" : principal.subject(), resourceId, owner);
            throw new AccessDeniedException(AccessRejectReason.RESOURCE_OWNER_MISMATCH);
        }
    }
}
