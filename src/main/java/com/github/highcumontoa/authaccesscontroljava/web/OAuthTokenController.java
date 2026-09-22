package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import com.github.highcumontoa.authaccesscontroljava.token.IssuedTokenSet;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.TokenAuthService;
import com.github.highcumontoa.authaccesscontroljava.web.dto.RevokeRequest;
import com.github.highcumontoa.authaccesscontroljava.web.dto.TokenRequest;
import com.github.highcumontoa.authaccesscontroljava.web.dto.TokenResponseDto;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 本地令牌端点（模拟 OAuth2 风格，不依赖任何外部授权服务器）：
 * POST /oauth/token   grant_type=password | client_credentials | refresh_token
 * POST /oauth/revoke  RFC 7009 风格撤销
 */
@RestController
public class OAuthTokenController {

    private static final Logger log = LoggerFactory.getLogger(OAuthTokenController.class);

    private final TokenAuthService tokenAuthService;

    public OAuthTokenController(TokenAuthService tokenAuthService) {
        this.tokenAuthService = tokenAuthService;
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
}
