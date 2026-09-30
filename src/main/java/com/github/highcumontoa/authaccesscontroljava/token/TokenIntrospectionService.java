package com.github.highcumontoa.authaccesscontroljava.token;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 只读令牌自检（RFC 7662 风格，供内部网关调用）。
 *
 * <p>关键约束：
 * <ul>
 *   <li>查询本身绝不改变令牌状态：不轮换、不撤销，也不更新会话 lastUsedAt；</li>
 *   <li>乱填/格式错误/为空的令牌都返回结构化 inactive 结果，绝不向调用方抛异常；</li>
 *   <li>无效原因彼此可区分：missing/malformed、unsupported_alg、bad_signature、unknown_signing_key、
 *       missing_claims、expired、issuer_mismatch、revoked、session_logged_out、stale；</li>
 *   <li>响应不回显令牌原文，也不包含任何签名密钥材料。</li>
 * </ul>
 */
@Service
public class TokenIntrospectionService {

    private static final Logger log = LoggerFactory.getLogger(TokenIntrospectionService.class);

    /** 自检结果；inactive=true 时 reason 给出可区分原因，身份字段为 null。 */
    public record Result(boolean active, String reason, String subject, String clientId,
                         String sessionId, Long exp, List<String> scopes) {

        static Result inactive(String reason) {
            return new Result(false, reason, null, null, null, null, List.of());
        }
    }

    private final AccessTokenService accessTokenService;
    private final RefreshTokenStore refreshTokenStore;

    public TokenIntrospectionService(AccessTokenService accessTokenService,
                                     RefreshTokenStore refreshTokenStore) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenStore = refreshTokenStore;
    }

    /**
     * 自检。永不抛异常：任何无法解析/校验失败的输入都转为 inactive + 稳定 reason。
     */
    public Result introspect(String compact, String expectedIssuer) {
        if (compact == null || compact.isBlank()) {
            return Result.inactive(RejectReason.MISSING_TOKEN.errorCode());
        }
        final AccessTokenClaims claims;
        try {
            claims = accessTokenService.verify(compact, expectedIssuer);
        } catch (RejectException ex) {
            log.debug("Introspection inactive: reason={}", ex.reason().errorCode());
            return Result.inactive(ex.reason().errorCode());
        } catch (RuntimeException ex) {
            // 任何意料之外的解析问题都收敛为结构化结论，不把堆栈/异常细节暴露给调用方。
            log.warn("Introspection failed unexpectedly, reporting malformed_token", ex);
            return Result.inactive(RejectReason.MALFORMED_TOKEN.errorCode());
        }

        RefreshTokenStore.FamilyStatus status =
                refreshTokenStore.familyStatus(claims.fam(), claims.gen());
        return switch (status) {
            case ACTIVE_CURRENT -> new Result(true, null, claims.sub(), claims.clientId(),
                    claims.fam(), claims.exp(), claims.scopes());
            case REVOKED -> Result.inactive(RejectReason.TOKEN_FAMILY_REVOKED.errorCode());
            case LOGGED_OUT -> Result.inactive(RejectReason.TOKEN_SESSION_LOGGED_OUT.errorCode());
            // ACTIVE_STALE（旧轮换代）/ UNKNOWN（族未知或已过期）统一归入 stale 族。
            case ACTIVE_STALE, UNKNOWN -> Result.inactive(RejectReason.TOKEN_FAMILY_STALE.errorCode());
        };
    }
}
