package com.github.highcumontoa.authaccesscontroljava.security;

import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.TokenAuthService;
import com.github.highcumontoa.authaccesscontroljava.web.dto.ErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 对 {@code /api/**} 强制 Bearer 认证：
 * 通过则把 {@link CurrentPrincipal} 放入请求属性；失败则在此直接写出结构化错误响应并终止请求。
 * {@code /oauth/**} 是令牌端点，其自身处理客户端认证，不经过此过滤器。
 */
@Component
public class AuthFilter extends OncePerRequestFilter {

    public static final String PRINCIPAL_ATTR = AuthFilter.class.getName() + ".principal";

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final TokenAuthService tokenAuthService;

    public AuthFilter(TokenAuthService tokenAuthService) {
        this.tokenAuthService = tokenAuthService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!request.getRequestURI().startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            CurrentPrincipal principal = tokenAuthService.authenticate(request.getHeader("Authorization"));
            request.setAttribute(PRINCIPAL_ATTR, principal);
            log.debug("Authenticated: subject={}, client={}, roles={}, scopes={}, jti={}",
                    principal.subject(), principal.clientId(), principal.roles(),
                    principal.scopes(), Maskers.fingerprint(principal.jti()));
            filterChain.doFilter(request, response);
        } catch (RejectException ex) {
            log.info("Access denied at authentication: reason={}, detail={}",
                    ex.reason().errorCode(), ex.getMessage());
            writeReject(response, ex.reason(), ex.getMessage());
        }
    }

    static void writeReject(HttpServletResponse response, RejectReason reason, String message)
            throws IOException {
        response.setStatus(reason.httpStatus().value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(JsonCodec.mapper().writeValueAsString(
                new ErrorResponse(reason.errorCode(), message)));
    }

    public static CurrentPrincipal principal(HttpServletRequest request) {
        return (CurrentPrincipal) request.getAttribute(PRINCIPAL_ATTR);
    }
}
