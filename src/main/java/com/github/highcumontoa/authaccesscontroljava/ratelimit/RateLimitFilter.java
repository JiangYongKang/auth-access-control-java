package com.github.highcumontoa.authaccesscontroljava.ratelimit;

import java.io.IOException;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.authaccesscontroljava.authz.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.web.AuthenticationFilter;
import com.github.highcumontoa.authaccesscontroljava.web.SecurityResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 对通过认证的 API 请求按主体（sub@cid）限流，超量返回 429 且原因可区分。
 */
@Component
@Order(2)
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        CurrentPrincipal principal = (CurrentPrincipal) request
                .getAttribute(AuthenticationFilter.PRINCIPAL_ATTRIBUTE);
        if (principal == null) {
            chain.doFilter(request, response);
            return;
        }
        String key = principal.subject() + "@" + principal.clientId();
        if (!rateLimiter.tryAcquire(key)) {
            response.setHeader("Retry-After", "60");
            SecurityResponse.write(objectMapper, response, 429,
                    "rate_limit_exceeded", RateLimitRejectReason.TOO_MANY_REQUESTS.name());
            return;
        }
        chain.doFilter(request, response);
    }
}
