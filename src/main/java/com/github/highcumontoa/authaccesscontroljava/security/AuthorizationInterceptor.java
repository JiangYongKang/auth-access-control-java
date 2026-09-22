package com.github.highcumontoa.authaccesscontroljava.security;

import com.github.highcumontoa.authaccesscontroljava.domain.AccountDirectory;
import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.domain.OwnedResource;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 鉴权拦截器（在认证过滤器之后执行）：按注解与路径变量依次判定角色、作用域、主体/资源归属，
 * 最后做主体维度限流。不同缺失给出不同 {@link RejectReason}，结论彼此可区分。
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final AccountDirectory accountDirectory;
    private final RateLimitService rateLimitService;

    public AuthorizationInterceptor(AccountDirectory accountDirectory,
                                    RateLimitService rateLimitService) {
        this.accountDirectory = accountDirectory;
        this.rateLimitService = rateLimitService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        CurrentPrincipal principal = AuthFilter.principal(request);
        if (principal == null) {
            // 正常不会发生（/api/** 已被过滤器保护），作为纵深防御。
            throw new RejectException(RejectReason.MISSING_TOKEN, "no authenticated principal");
        }

        checkRole(handlerMethod, principal);
        checkScope(handlerMethod, principal);
        checkSubjectScoped(handlerMethod, request, principal);
        checkRateLimit(principal);
        return true;
    }

    private void checkRole(HandlerMethod handlerMethod, CurrentPrincipal principal) {
        RequireRole annotation = handlerMethod.getMethodAnnotation(RequireRole.class);
        if (annotation == null) {
            annotation = handlerMethod.getBeanType().getAnnotation(RequireRole.class);
        }
        if (annotation == null) {
            return;
        }
        boolean matched = Arrays.stream(annotation.value()).anyMatch(principal.roles()::contains);
        if (!matched) {
            log.info("Role denied: subject={}, has={}, requiredOneOf={}",
                    principal.subject(), principal.roles(), Arrays.toString(annotation.value()));
            throw new RejectException(RejectReason.FORBIDDEN_ROLE,
                    "insufficient role; requires one of " + Arrays.toString(annotation.value()));
        }
    }

    private void checkScope(HandlerMethod handlerMethod, CurrentPrincipal principal) {
        RequireScope annotation = handlerMethod.getMethodAnnotation(RequireScope.class);
        if (annotation == null) {
            annotation = handlerMethod.getBeanType().getAnnotation(RequireScope.class);
        }
        if (annotation == null) {
            return;
        }
        boolean matched = Arrays.stream(annotation.value()).anyMatch(principal.scopes()::contains);
        if (!matched) {
            log.info("Scope denied: subject={}, has={}, requiredOneOf={}",
                    principal.subject(), principal.scopes(), Arrays.toString(annotation.value()));
            throw new RejectException(RejectReason.FORBIDDEN_SCOPE,
                    "insufficient scope; requires one of " + Arrays.toString(annotation.value()));
        }
    }

    private void checkSubjectScoped(HandlerMethod handlerMethod, HttpServletRequest request,
                                    CurrentPrincipal principal) {
        SubjectScoped annotation = handlerMethod.getMethodAnnotation(SubjectScoped.class);
        if (annotation == null) {
            return;
        }
        if (principal.roles().contains("ADMIN")) {
            return;
        }
        Map<String, String> pathVariables = extractPathVariables(request);
        String value = pathVariables.get(annotation.pathVariable());
        if (value == null) {
            throw new RejectException(RejectReason.INVALID_REQUEST,
                    "missing path variable: " + annotation.pathVariable());
        }

        if ("userId".equals(annotation.pathVariable())) {
            // 直接以用户标识定位资源：主体必须一致。
            if (!principal.subject().equals(value)) {
                log.info("Subject mismatch: token subject={} requests resource of userId={}",
                        principal.subject(), value);
                throw new RejectException(RejectReason.TOKEN_SUBJECT_MISMATCH,
                        "token subject '" + principal.subject()
                                + "' is not allowed to access data of '" + value + "'");
            }
            return;
        }

        // 否则按"资源归属"判定：资源不存在或 owner 与主体不一致都拒绝。
        OwnedResource resource = accountDirectory.findResource(value)
                .orElseThrow(() -> new RejectException(RejectReason.FORBIDDEN_OWNER,
                        "resource not found or not owned by caller: " + value));
        if (!resource.ownerUserId().equals(principal.subject())) {
            log.info("Ownership denied: subject={}, resource={}, owner={}",
                    principal.subject(), resource.id(), resource.ownerUserId());
            throw new RejectException(RejectReason.FORBIDDEN_OWNER,
                    "resource " + resource.id() + " is owned by another subject");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> extractPathVariables(HttpServletRequest request) {
        Object value = request.getAttribute(
                org.springframework.web.servlet.HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        return value instanceof Map ? (Map<String, String>) value : Map.of();
    }

    private void checkRateLimit(CurrentPrincipal principal) {
        if (!rateLimitService.tryAcquire(principal.subject())) {
            throw new RejectException(RejectReason.RATE_LIMITED,
                    "too many requests for subject " + principal.subject()
                            + "; allowed " + rateLimitService.maxRequests()
                            + " per " + rateLimitService.windowSeconds() + "s window");
        }
    }
}
