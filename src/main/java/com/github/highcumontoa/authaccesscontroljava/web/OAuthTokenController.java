package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import com.github.highcumontoa.authaccesscontroljava.session.IntrospectionService;
import com.github.highcumontoa.authaccesscontroljava.token.IssuedTokenSet;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.TokenAuthService;
import com.github.highcumontoa.authaccesscontroljava.web.dto.RevokeRequest;
import com.github.highcumontoa.authaccesscontroljava.web.dto.TokenRequest;
import com.github.highcumontoa.authaccesscontroljava.web.dto.TokenResponseDto;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 本地令牌端点（模拟 OAuth2 风格，不依赖任何外部授权服务器）：
 * POST /oauth/token       grant_type=password | client_credentials | refresh_token
 * POST /oauth/revoke      RFC 7009 风格撤销
 * POST /oauth/introspect  只读令牌自检（RFC 7662 风格，供内部网关使用）
 */
@RestController
public class OAuthTokenController {

    private static final Logger log = LoggerFactory.getLogger(OAuthTokenController.class);

    private final TokenAuthService tokenAuthService;
    private final IntrospectionService introspectionService;

    public OAuthTokenController(TokenAuthService tokenAuthService,
                                IntrospectionService introspectionService) {
        this.tokenAuthService = tokenAuthService;
        this.introspectionService = introspectionService;
    }

    @PostMapping("/oauth/token")
    public TokenResponseDto token(@RequestBody(required = false) TokenRequest request) {
        if (request == null) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "JSON request body is required");
        }
        String grantType = request.getGrant_type();
        if (grantType == null || grantType.isBlank()) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "grant_type is required");
        }

        IssuedTokenSet issued = switch (grantType) {
            case "password" -> tokenAuthService.passwordGrant(
                    request.getClient_id(), request.getClient_secret(),
                    request.getUsername(), request.getPassword(), request.getScope());
            case "client_credentials" -> tokenAuthService.clientCredentialsGrant(
                    request.getClient_id(), request.getClient_secret(), request.getScope());
            case "refresh_token" -> tokenAuthService.refreshGrant(
                    request.getClient_id(), request.getClient_secret(), request.getRefresh_token());
            default -> throw new RejectException(RejectReason.UNSUPPORTED_GRANT_TYPE,
                    "unsupported grant_type: " + grantType);
        };

        log.info("Token issued: grantType={}, client={}, family={}, accessToken={}",
                grantType, request.getClient_id(), issued.familyId(),
                Maskers.maskToken(issued.accessToken()));
        return new TokenResponseDto(issued.accessToken(), issued.refreshToken(),
                issued.tokenType(), issued.expiresIn());
    }

    @PostMapping("/oauth/revoke")
    public Map<String, String> revoke(@RequestBody(required = false) RevokeRequest request) {
        if (request == null) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "JSON request body is required");
        }
        tokenAuthService.revokeGrant(request.getClient_id(), request.getClient_secret(),
                request.getToken(), request.getToken_type_hint());
        // RFC 7009：无论令牌是否存在都返回 200。
        return Map.of("status", "revoked");
    }

    /**
     * 只读令牌自检（RFC 7662 风格）：认证调用方客户端后，返回令牌当前是否有效及无效原因。
     *
     * <p>与内网网关的约定：该端点对「令牌层面」的任何输入都<b>不返回 4xx/5xx</b>——
     * 没带令牌（字段缺失或为空）、乱填、畸形令牌，一律是 HTTP 200 + {@code active=false}，
     * 用 {@code reason} 说明为什么无效；响应绝不回显令牌原文或任何密钥信息。
     * 仅当请求确实携带了待检令牌时才要求客户端认证（沿用撤销端点的反匿名探测约定，
     * 凭据错误仍为 401 {@code invalid_client}）。
     */
    @PostMapping("/oauth/introspect")
    public Map<String, Object> introspect(@RequestBody(required = false) String rawBody) {
        // 宽容解析请求体：body 缺失或不是合法 JSON 时都按「没带令牌」处理，绝不向网关抛 4xx。
        RevokeRequest request = parseIntrospectBody(rawBody);
        String token = request == null ? null : request.getToken();
        if (token == null || token.isBlank()) {
            log.info("Introspection without token: 200 active=false, reason=missing_token");
            return inactiveBody("missing_token");
        }

        // 与撤销端点一致：必须先认证客户端，避免匿名探测。
        tokenAuthService.requireClient(request.getClient_id(), request.getClient_secret());

        IntrospectionService.Result result = introspectionService.introspect(token);
        log.info("Introspection processed: token={}, active={}, reason={}",
                Maskers.maskToken(token), result.active(), result.reason());

        if (!result.active()) {
            return inactiveBody(result.reason());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("active", true);
        body.put("sub", result.subject());
        body.put("client_id", result.clientId());
        body.put("exp", result.exp());
        body.put("scope", result.scopes() == null ? "" : String.join(" ", result.scopes()));
        return body;
    }

    private static Map<String, Object> inactiveBody(String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("active", false);
        body.put("reason", reason);
        return body;
    }

    /** 尽力把请求体解析成 {@link RevokeRequest}；任何失败（空体/非法 JSON/类型不符）都返回 null。 */
    private static RevokeRequest parseIntrospectBody(String rawBody) {
        if (rawBody == null || rawBody.isBlank()) {
            return null;
        }
        try {
            return com.github.highcumontoa.authaccesscontroljava.support.JsonCodec.mapper()
                    .readValue(rawBody, RevokeRequest.class);
        } catch (Exception e) {
            return null;
        }
    }
}
