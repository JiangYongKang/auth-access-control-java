package com.github.highcumontoa.authaccesscontroljava.session;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 只读令牌自检（面向内网网关，RFC 7662 风格）：丢一个令牌进来，返回它当前是否有效，
 * 无效时给出可区分的原因类别。
 *
 * <p>关键安全性质：
 * <ul>
 *   <li><b>只读</b>：不做轮换、不撤销、不写任何状态，也不更新会话的「最近使用」时间；</li>
 *   <li><b>不抛异常</b>：乱填、格式错误、无法解析的令牌一律得到 {@code active=false} 而非 5xx；</li>
 *   <li><b>不泄密</b>：结果只含主体/客户端/过期时间等非敏感元数据，绝不回显令牌原文或签名密钥；</li>
 *   <li>无效原因细分：malformed / unsupported_alg / bad_signature / unknown_signing_key /
 *       missing_claims / expired / issuer_mismatch / token_revoked / session_revoked / family_stale。
 *       其中「令牌本身被显式撤销」(token_revoked) 与「会话被注销导致令牌失效」
 *       (session_revoked) 是两个互不混淆的原因，网关可据此采取不同策略。</li>
 * </ul>
 */
@Service
public class IntrospectionService {

    private static final Logger log = LoggerFactory.getLogger(IntrospectionService.class);

    private final AccessTokenService accessTokenService;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthProperties props;

    public IntrospectionService(AccessTokenService accessTokenService,
                                RefreshTokenStore refreshTokenStore, AuthProperties props) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenStore = refreshTokenStore;
        this.props = props;
    }

    /** 自检结果。无效时 {@code active=false} 且 {@code reason} 给出原因类别；有效时 reason 为 null。 */
    public record Result(boolean active, String reason, String subject, String clientId,
                         Long exp, List<String> scopes) {
        static Result invalid(String reason) {
            return new Result(false, reason, null, null, null, null);
        }
    }

    public Result introspect(String compact) {
        if (compact == null || compact.isBlank()) {
            return Result.invalid("missing_token");
        }
        final AccessTokenClaims claims;
        try {
            claims = accessTokenService.verify(compact, props.getSecurity().getIssuer());
        } catch (RejectException ex) {
            RejectReason r = ex.reason();
            String reason = switch (r) {
                case MISSING_TOKEN -> "missing_token";
                case MALFORMED_TOKEN -> "malformed";
                case UNSUPPORTED_ALG -> "unsupported_alg";
                case BAD_SIGNATURE -> "bad_signature";
                case UNKNOWN_SIGNING_KEY -> "unknown_signing_key";
                case MISSING_CLAIMS -> "missing_claims";
                case TOKEN_EXPIRED -> "expired";
                case TOKEN_ISSUER_MISMATCH -> "issuer_mismatch";
                default -> "invalid_token";
            };
            log.debug("Introspection: token inactive, reason={}", reason);
            return Result.invalid(reason);
        } catch (RuntimeException ex) {
            // 任何意料之外的解析问题都收敛成 inactive，绝不把异常抛给调用方。
            log.info("Introspection: token inactive due to unparseable content");
            return Result.invalid("malformed");
        }

        // 令牌自身合法，再判定会话/族状态（与会话注销、轮换、撤销保持同一结论）。
        RefreshTokenStore.FamilyStatus status =
                refreshTokenStore.familyStatus(claims.fam(), claims.gen());
        if (status == RefreshTokenStore.FamilyStatus.REVOKED) {
            // 同样是「族已撤销」，按持久化的撤销起因把两种情形明确分开：
            //  - 令牌端点显式撤销（/oauth/revoke）         -> token_revoked
            //  - 会话被管理端注销/踢下线（含注销全部）      -> session_revoked
            RefreshTokenStore.RevocationCause cause =
                    refreshTokenStore.revocationCause(claims.fam());
            String reason = cause == RefreshTokenStore.RevocationCause.SESSION_LOGOUT
                    ? "session_revoked"
                    : "token_revoked";
            log.debug("Introspection: token inactive, reason={}", reason);
            return Result.invalid(reason);
        }
        if (status != RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT) {
            return Result.invalid("family_stale");
        }

        return new Result(true, null, claims.sub(), claims.clientId(),
                claims.exp(), List.copyOf(claims.scopes()));
    }
}
