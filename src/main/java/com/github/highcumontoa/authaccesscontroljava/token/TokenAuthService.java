package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.domain.AccountDirectory;
import com.github.highcumontoa.authaccesscontroljava.domain.ClientApp;
import com.github.highcumontoa.authaccesscontroljava.domain.CurrentPrincipal;
import com.github.highcumontoa.authaccesscontroljava.domain.UserAccount;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 令牌认证编排服务：令牌端点的三种 grant、撤销，以及受保护请求的访问令牌认证都在此完成。
 * 不访问任何外部服务；所有凭据来自本地 {@link AccountDirectory}，所有刷新状态来自本地存储。
 */
@Service
public class TokenAuthService {

    private static final Logger log = LoggerFactory.getLogger(TokenAuthService.class);
    private static final String CLIENT_SUBJECT_PREFIX = "client:";

    private final AccessTokenService accessTokenService;
    private final RefreshTokenStore refreshTokenStore;
    private final AccountDirectory accounts;
    private final AuthProperties props;
    private final Clock clock;

    public TokenAuthService(AccessTokenService accessTokenService, RefreshTokenStore refreshTokenStore,
                            AccountDirectory accounts, AuthProperties props, Clock clock) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenStore = refreshTokenStore;
        this.accounts = accounts;
        this.props = props;
        this.clock = clock;
    }

    public IssuedTokenSet passwordGrant(String clientId, String clientSecret,
                                        String username, String password, String requestedScope) {
        ClientApp client = authenticateClient(clientId, clientSecret);
        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            throw new RejectException(RejectReason.INVALID_REQUEST,
                    "username and password are required for password grant");
        }
        UserAccount user = accounts.findUserByUsername(username)
                .orElseThrow(() -> new RejectException(RejectReason.INVALID_GRANT,
                        "unknown username or wrong password"));
        if (!accounts.checkUserPassword(user, password)) {
            log.info("Password grant rejected: bad password for user={}", username);
            throw new RejectException(RejectReason.INVALID_GRANT, "unknown username or wrong password");
        }
        List<String> scopes = resolveScopes(client, requestedScope);
        return issueSet(user.id(), client, user.roles(), scopes, true);
    }

    public IssuedTokenSet clientCredentialsGrant(String clientId, String clientSecret,
                                                 String requestedScope) {
        ClientApp client = authenticateClient(clientId, clientSecret);
        List<String> scopes = resolveScopes(client, requestedScope);
        List<String> roles = List.of("CLIENT");
        String subject = CLIENT_SUBJECT_PREFIX + client.clientId();
        // 客户端凭据模式不与终端用户交互，按 RFC 6749 不签发刷新令牌。
        return issueSet(subject, client, roles, scopes, false);
    }

    public IssuedTokenSet refreshGrant(String clientId, String clientSecret, String refreshToken) {
        ClientApp client = authenticateClient(clientId, clientSecret);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "refresh_token is required");
        }

        RefreshTokenStore.RotationResult result = refreshTokenStore.consume(refreshToken, client.clientId());
        switch (result.outcome()) {
            case UNKNOWN -> throw new RejectException(RejectReason.INVALID_GRANT,
                    "refresh token is unknown");
            case CLIENT_MISMATCH -> throw new RejectException(RejectReason.INVALID_GRANT_CLIENT_MISMATCH,
                    "refresh token was not issued to this client");
            case EXPIRED -> throw new RejectException(RejectReason.INVALID_GRANT_EXPIRED,
                    "refresh token family has expired");
            case REVOKED -> throw new RejectException(RejectReason.INVALID_GRANT_REVOKED,
                    "refresh token family has been revoked");
            case REPLAYED -> throw new RejectException(RejectReason.INVALID_GRANT_REPLAYED,
                    "refresh token was already rotated; replay of an old refresh token is rejected");
            case SUCCESS -> {
                RefreshFamily family = result.family();
                String accessToken = mintAccessToken(family.getSubject(), client.clientId(),
                        family.getFamilyId(), result.nextToken().generation(),
                        family.getRoles(), family.getScopes());
                log.info("Refresh grant success: family={}, gen={}, subject={}",
                        family.getFamilyId(), family.getGeneration(), family.getSubject());
                return new IssuedTokenSet(accessToken, result.nextToken().rawToken(),
                        "Bearer", props.getToken().getAccessTtlSeconds(), family.getFamilyId());
            }
            default -> throw new IllegalStateException("unexpected rotation outcome: " + result.outcome());
        }
    }

    public void revokeGrant(String clientId, String clientSecret, String token, String tokenTypeHint) {
        // RFC 7009：必须先认证客户端；token 不属于该客户端时按规范仍返回 200（不泄露令牌归属）。
        ClientApp client = authenticateClient(clientId, clientSecret);
        if (token == null || token.isBlank()) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "token is required");
        }
        // 依次尝试从"刷新令牌前缀 / 访问令牌 fam 声明 / 裸 familyId"定位族；
        // 族归属于其他客户端时按 RFC 7009 静默处理，不向调用方泄露令牌归属。
        String familyId = resolveFamilyId(token);
        if (familyId != null) {
            refreshTokenStore.findByFamilyId(familyId).ifPresent(family -> {
                if (client.clientId().equals(family.getClientId())) {
                    refreshTokenStore.revoke(familyId,
                            "explicit_revoke:" + (tokenTypeHint == null ? "unspecified" : tokenTypeHint));
                }
            });
        }
        log.info("Revocation processed for token={} hint={}",
                Maskers.maskToken(token), tokenTypeHint);
    }

    /** 不做验签地从令牌形态中提取族标识：刷新令牌取点号前缀，访问令牌取 payload 的 fam 声明。 */
    private String resolveFamilyId(String token) {
        int dot = token.indexOf('.');
        if (dot <= 0) {
            return null;
        }
        String beforeFirstDot = token.substring(0, dot);
        // 刷新令牌第一段是 UUID（含连字符）；JWT header 段是 base64url（不含 '.' 以外分隔，且以 eyJ 开头）
        if (beforeFirstDot.contains("-") && token.chars().filter(c -> c == '.').count() == 1) {
            return beforeFirstDot;
        }
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length == 3) {
                byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
                var node = com.github.highcumontoa.authaccesscontroljava.support.JsonCodec
                        .mapper().readTree(payload);
                String fam = node.path("fam").asText(null);
                if (fam != null && !fam.isBlank()) {
                    return fam;
                }
            }
        } catch (Exception ignored) {
            // 形态无法识别时按"无可撤销目标"静默处理
        }
        return null;
    }

    /**
     * 认证受保护请求上的 Bearer 访问令牌。
     * 令牌自身校验失败原因由 {@link AccessTokenService#verify} 区分；
     * 这里追加族状态判定：已撤销 → TOKEN_FAMILY_REVOKED，旧轮换/未知族 → TOKEN_FAMILY_STALE。
     */
    public CurrentPrincipal authenticate(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            throw new RejectException(RejectReason.MISSING_TOKEN,
                    "Authorization header is missing");
        }
        if (!authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new RejectException(RejectReason.MALFORMED_TOKEN,
                    "Authorization header must use the Bearer scheme");
        }
        String compact = authorizationHeader.substring(7).trim();
        if (compact.isEmpty()) {
            throw new RejectException(RejectReason.MISSING_TOKEN, "Bearer token is empty");
        }

        AccessTokenClaims claims = accessTokenService.verify(compact, props.getSecurity().getIssuer());

        RefreshTokenStore.FamilyStatus status =
                refreshTokenStore.familyStatus(claims.fam(), claims.gen());
        if (status == RefreshTokenStore.FamilyStatus.REVOKED) {
            throw new RejectException(RejectReason.TOKEN_FAMILY_REVOKED,
                    "the token family was revoked; all tokens of this family are rejected");
        }
        if (status != RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT) {
            // ACTIVE_STALE：令牌属于已被轮换掉的旧代；UNKNOWN：族不存在或已过期。
            throw new RejectException(RejectReason.TOKEN_FAMILY_STALE,
                    "access token is not from the current family generation (" + status + ")");
        }

        return new CurrentPrincipal(claims.sub(), claims.clientId(),
                new HashSet<>(claims.roles()), new HashSet<>(claims.scopes()),
                claims.jti(), claims.gen());
    }

    private ClientApp authenticateClient(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank()) {
            throw new RejectException(RejectReason.INVALID_REQUEST, "client_id is required");
        }
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new RejectException(RejectReason.INVALID_CLIENT, "client_secret is required");
        }
        ClientApp client = accounts.findClient(clientId)
                .orElseThrow(() -> new RejectException(RejectReason.INVALID_CLIENT,
                        "unknown client_id"));
        if (!accounts.checkClientSecret(client, clientSecret)) {
            log.info("Client authentication failed: client={}", clientId);
            throw new RejectException(RejectReason.INVALID_CLIENT, "wrong client_secret");
        }
        return client;
    }

    private List<String> resolveScopes(ClientApp client, String requestedScope) {
        List<String> requested = parseScopes(requestedScope);
        if (requested.isEmpty()) {
            return List.copyOf(client.allowedScopes());
        }
        List<String> granted = new ArrayList<>();
        for (String scope : requested) {
            if (client.allowedScopes().contains(scope)) {
                granted.add(scope);
            } else {
                throw new RejectException(RejectReason.INVALID_SCOPE,
                        "scope '" + scope + "' is not allowed for this client");
            }
        }
        return List.copyOf(granted);
    }

    private static List<String> parseScopes(String requestedScope) {
        if (requestedScope == null || requestedScope.isBlank()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String part : requestedScope.trim().split("\\s+")) {
            if (seen.add(part)) {
                result.add(part);
            }
        }
        return result;
    }

    private IssuedTokenSet issueSet(String subject, ClientApp client, List<String> roles,
                                    List<String> scopes, boolean withRefreshToken) {
        RefreshTokenStore.StoredToken stored = null;
        String familyId;
        long generation;
        if (withRefreshToken) {
            stored = refreshTokenStore.create(subject, client.clientId(),
                    props.getToken().getRefreshTtlSeconds(), roles, scopes);
            familyId = stored.familyId();
            generation = stored.generation();
        } else {
            // 客户端凭据族仅用于承载访问令牌的代际状态，不签发刷新令牌原文。
            stored = refreshTokenStore.create(subject, client.clientId(),
                    props.getToken().getAccessTtlSeconds() + 60, roles, scopes);
            familyId = stored.familyId();
            generation = stored.generation();
        }
        String accessToken = mintAccessToken(subject, client.clientId(), familyId, generation, roles, scopes);
        return new IssuedTokenSet(accessToken, withRefreshToken ? stored.rawToken() : null,
                "Bearer", props.getToken().getAccessTtlSeconds(), familyId);
    }

    private String mintAccessToken(String subject, String clientId, String familyId, long generation,
                                   List<String> roles, List<String> scopes) {
        long now = clock.epochSeconds();
        AccessTokenClaims claims = new AccessTokenClaims(
                props.getSecurity().getIssuer(),
                subject,
                "local-resource-api",
                UUID.randomUUID().toString(),
                clientId,
                familyId,
                now,
                now + props.getToken().getAccessTtlSeconds(),
                generation,
                roles,
                scopes);
        return accessTokenService.issue(claims);
    }

    /** 供上层做"主体与请求资源是否相符"判定。 */
    public static boolean isClientSubject(String subject) {
        return subject != null && subject.startsWith(CLIENT_SUBJECT_PREFIX);
    }
}
