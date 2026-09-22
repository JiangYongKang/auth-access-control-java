package com.github.highcumontoa.authaccesscontroljava.web;

import java.io.IOException;
import java.util.List;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.authaccesscontroljava.authz.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.token.TokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.TokenRejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.TokenService;
import com.github.highcumontoa.authaccesscontroljava.token.TokenValidationException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 对受保护资源（/api/**）校验 Bearer 访问令牌，并把主体放入请求属性。
 * 令牌缺失/过期/篡改/主体不符/缺声明/已拒绝等原因分别返回不同 reason。
 */
@Component
@Order(1)
public class AuthenticationFilter extends OncePerRequestFilter {

    public static final String PRINCIPAL_ATTRIBUTE = CurrentPrincipal.class.getName();

    private final TokenService tokenService;
    private final ObjectMapper objectMapper;

    public AuthenticationFilter(TokenService tokenService, ObjectMapper objectMapper) {
        this.tokenService = tokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            deny(response, TokenRejectReason.MISSING_AUTHORIZATION);
            return;
        }
        if (!header.startsWith("Bearer ")) {
            deny(response, TokenRejectReason.MALFORMED);
            return;
        }
        String token = header.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            deny(response, TokenRejectReason.MALFORMED);
            return;
        }
        try {
            TokenClaims claims = tokenService.verify(token);
            CurrentPrincipal principal = new CurrentPrincipal(
                    claims.subject(), claims.clientId(),
                    List.copyOf(claims.roles()), List.copyOf(claims.scopes()), claims.jti());
            request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        } catch (TokenValidationException ex) {
            deny(response, ex.getReason());
            return;
        }
        chain.doFilter(request, response);
    }

    private void deny(HttpServletResponse response, TokenRejectReason reason) throws IOException {
        org.slf4j.LoggerFactory.getLogger(AuthenticationFilter.class)
                .warn("拒绝访问: path 受保护, reason={}", reason);
        SecurityResponse.write(objectMapper, response, HttpServletResponse.SC_UNAUTHORIZED,
                "invalid_token", reason.name());
    }
}
