package com.github.highcumontoa.authaccesscontroljava.token;

import java.time.Clock;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.security.SecretHasher;
import com.github.highcumontoa.authaccesscontroljava.user.UserDirectory;

/**
 * 刷新令牌的签发、并发安全轮换与撤销。
 *
 * <p>原始刷新令牌仅在创建时返回给客户端一次；服务端只保存其 SHA-256 指纹。
 * 轮换成功后产生新的访问令牌与新的刷新令牌；旧访问令牌的 jti 在原子状态翻转中
 * 立即进入拒绝清单。</p>
 */
@Component
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final AuthProperties properties;
    private final Clock clock;
    private final TokenStateStore stateStore;
    private final TokenService tokenService;
    private final UserDirectory userDirectory;

    public RefreshTokenService(AuthProperties properties, Clock clock, TokenStateStore stateStore,
                               TokenService tokenService, UserDirectory userDirectory) {
        this.properties = properties;
        this.clock = clock;
        this.stateStore = stateStore;
        this.tokenService = tokenService;
        this.userDirectory = userDirectory;
    }

    /**
     * 为密码授权创建首个刷新令牌家族。
     *
     * @param currentAccessJti 配套访问令牌的 jti
     * @param scopes           授权作用域（刷新后继续生效）
     */
    public IssuedRefresh issueRefresh(String subject, String clientId, String currentAccessJti,
                                      List<String> scopes) {
        String raw = SecretHasher.randomToken();
        String jti = SecretHasher.randomId();
        long expiresAt = clock.instant().toEpochMilli() + properties.getRefresh().getTtl().toMillis();
        stateStore.createFamily(subject, clientId, SecretHasher.sha256Base64(raw), jti, expiresAt,
                currentAccessJti, scopes);
        log.info("签发刷新令牌: sub={}, cid={}, jti={}", subject, clientId, jti);
        return new IssuedRefresh(raw, jti);
    }

    /**
     * 轮换：同一刷新令牌在并发/重复使用时最多成功一次，其余按可区分原因拒绝。
     */
    public RotationResult rotate(String rawRefreshToken, String clientId) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new RefreshRejectedException(RefreshRejectReason.NOT_FOUND);
        }
        String oldHash = SecretHasher.sha256Base64(rawRefreshToken);

        // 预生成新令牌材料（含新访问令牌 jti）；轮换失败时这些材料不落库，天然作废
        String newRaw = SecretHasher.randomToken();
        String newRefreshJti = SecretHasher.randomId();
        String newAccessJti = java.util.UUID.randomUUID().toString().replace("-", "");
        long newExpiresAt = clock.instant().toEpochMilli() + properties.getRefresh().getTtl().toMillis();

        // 原子轮换：旧刷新令牌翻转 + 旧访问 jti 拒绝 + 新材料登记，在同一把锁内完成
        TokenStateStore.RotationOutcome outcome = stateStore.rotate(
                oldHash, clientId, SecretHasher.sha256Base64(newRaw), newRefreshJti,
                newExpiresAt, newAccessJti);

        List<String> roles = userDirectory.findUser(outcome.subject())
                .map(UserDirectory.AuthenticatedUser::roles)
                .orElse(List.of());
        String accessToken = tokenService.issue(
                new TokenService.TokenClaimsData(outcome.subject(), outcome.clientId(), roles,
                        outcome.scopes()),
                newAccessJti);

        IssuedTokenSet tokens = new IssuedTokenSet(
                accessToken, newRaw, "Bearer",
                properties.getToken().getTtl().getSeconds(), newAccessJti, newRefreshJti);
        return new RotationResult(tokens, outcome.oldStatus(), outcome.replayed());
    }

    /**
     * 撤销家族（登出）。
     */
    public void revoke(String rawRefreshToken, String clientId) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new RefreshRejectedException(RefreshRejectReason.NOT_FOUND);
        }
        stateStore.revokeFamily(SecretHasher.sha256Base64(rawRefreshToken), clientId);
        log.info("刷新令牌家族已撤销: cid={}", clientId);
    }

    public record IssuedRefresh(String refreshToken, String refreshJti) {
    }
}
