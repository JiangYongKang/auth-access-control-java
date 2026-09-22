package com.github.highcumontoa.authaccesscontroljava.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.github.highcumontoa.authaccesscontroljava.token.RefreshRejectedException;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.RotationResult;
import com.github.highcumontoa.authaccesscontroljava.token.TokenService;
import com.github.highcumontoa.authaccesscontroljava.user.UserDirectory;

/**
 * OAuth2 风格令牌端点：密码授权、刷新轮换、撤销（登出）。
 * 所有令牌请求都必须先通过客户端认证（client_id + client_secret）。
 */
@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserDirectory userDirectory;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserDirectory userDirectory, TokenService tokenService,
                          RefreshTokenService refreshTokenService) {
        this.userDirectory = userDirectory;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/oauth/token")
    public Map<String, Object> token(@RequestParam("grant_type") String grantType,
                                     @RequestParam(value = "client_id", required = false) String clientId,
                                     @RequestParam(value = "client_secret", required = false) String clientSecret,
                                     @RequestParam(value = "username", required = false) String username,
                                     @RequestParam(value = "password", required = false) String password,
                                     @RequestParam(value = "refresh_token", required = false) String refreshToken,
                                     @RequestParam(value = "scope", required = false) String scope) {
        UserDirectory.AuthenticatedClient client = authenticateClient(clientId, clientSecret);

        if ("password".equals(grantType)) {
            if (username == null || password == null) {
                throw new OAuthException("invalid_request");
            }
            UserDirectory.AuthenticatedUser user = userDirectory
                    .authenticateUser(username, password.toCharArray())
                    .orElseThrow(() -> new OAuthException("invalid_grant"));

            List<String> grantedScopes = resolveScopes(client, scope);
            String accessJti = java.util.UUID.randomUUID().toString().replace("-", "");
            String accessToken = tokenService.issue(new TokenService.TokenClaimsData(
                    user.username(), client.clientId(), user.roles(), grantedScopes), accessJti);
            RefreshTokenService.IssuedRefresh refresh = refreshTokenService.issueRefresh(
                    user.username(), client.clientId(), accessJti, grantedScopes);

            log.info("密码授权成功: sub={}, cid={}, scopes={}", user.username(), client.clientId(),
                    grantedScopes);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", accessToken);
            body.put("refresh_token", refresh.refreshToken());
            body.put("token_type", "Bearer");
            body.put("scope", String.join(" ", grantedScopes));
            body.put("access_jti", accessJti);
            return body;
        }

        if ("refresh_token".equals(grantType)) {
            if (refreshToken == null || refreshToken.isBlank()) {
                throw new OAuthException("invalid_request");
            }
            RotationResult result;
            try {
                result = refreshTokenService.rotate(refreshToken, client.clientId());
            } catch (RefreshRejectedException ex) {
                // 刷新失败原因经 reason 字段透传，可区分
                log.warn("刷新被拒绝: cid={}, reason={}", client.clientId(), ex.getReason());
                throw new RefreshOAuthException(ex.getReason().name());
            }
            log.info("刷新轮换成功: cid={}, oldStatus={}", client.clientId(), result.oldStatus());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", result.tokens().accessToken());
            body.put("refresh_token", result.tokens().refreshToken());
            body.put("token_type", result.tokens().tokenType());
            body.put("expires_in", result.tokens().expiresIn());
            body.put("access_jti", result.tokens().jti());
            return body;
        }

        throw new OAuthException("unsupported_grant_type");
    }

    @PostMapping("/oauth/revoke")
    public Map<String, Object> revoke(@RequestParam("client_id") String clientId,
                                      @RequestParam("client_secret") String clientSecret,
                                      @RequestParam("token") String token) {
        UserDirectory.AuthenticatedClient client = authenticateClient(clientId, clientSecret);
        try {
            refreshTokenService.revoke(token, client.clientId());
        } catch (RefreshRejectedException ex) {
            log.warn("撤销被拒绝: cid={}, reason={}", client.clientId(), ex.getReason());
            throw new RefreshOAuthException(ex.getReason().name());
        }
        return Map.of("revoked", true);
    }

    private UserDirectory.AuthenticatedClient authenticateClient(String clientId, String clientSecret) {
        if (clientId == null || clientSecret == null) {
            throw new OAuthException("invalid_request");
        }
        return userDirectory.authenticateClient(clientId, clientSecret.toCharArray())
                .orElseThrow(() -> new OAuthException("invalid_client"));
    }

    private List<String> resolveScopes(UserDirectory.AuthenticatedClient client, String requested) {
        Set<String> allowed = Set.copyOf(client.scopes());
        if (requested == null || requested.isBlank()) {
            return List.copyOf(allowed);
        }
        List<String> wanted = List.of(requested.trim().split("\\s+"));
        List<String> granted = wanted.stream().filter(allowed::contains).collect(Collectors.toList());
        if (granted.size() != wanted.size()) {
            throw new OAuthException("invalid_scope");
        }
        return granted;
    }

}
