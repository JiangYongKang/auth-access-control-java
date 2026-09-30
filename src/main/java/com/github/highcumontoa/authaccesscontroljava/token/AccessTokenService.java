package com.github.highcumontoa.authaccesscontroljava.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 自包含的紧凑 JWT（HS256）服务，不依赖任何外部授权服务器。
 *
 * <p>校验按固定顺序进行，每种失败都映射到不同的 {@link RejectReason}，结论可解释、可复现：
 * <pre>
 *   结构非法 → MALFORMED_TOKEN
 *   头部 alg 不受支持 → UNSUPPORTED_ALG
 *   kid 对应密钥已摘除/未配置 → UNKNOWN_SIGNING_KEY（与下面的签名不匹配明确分开）
 *   签名不匹配（密钥仍在，但载荷/签名被篡改） → BAD_SIGNATURE
 *   载荷解析失败/缺少必需声明 → MALFORMED_TOKEN / MISSING_CLAIMS
 *   已过期 → TOKEN_EXPIRED
 *   签发者不符 → TOKEN_ISSUER_MISMATCH
 * </pre>
 * 头部含 {@code kid}，标识签发所用密钥；无 kid 的旧令牌按兼容密钥 id "default" 处理。
 * */
@Service
public class AccessTokenService {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenService.class);

    static final String ALG = "HS256";
    private static final Set<String> REQUIRED_CLAIMS =
            Set.of("iss", "sub", "jti", "iat", "exp", "clientId", "fam", "gen");

    private final SigningKeyRing keyRing;
    private final Clock clock;
    private final Base64.Encoder b64url = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64urlDecoder = Base64.getUrlDecoder();

    public AccessTokenService(SigningKeyRing keyRing, Clock clock) {
        this.keyRing = keyRing;
        this.clock = clock;
    }

    public String issue(AccessTokenClaims claims) {
        try {
            // 签发始终使用密钥环当前密钥，kid 也以当前密钥为准（不信任外部传入值）。
            SigningKey active = keyRing.activeKey();
            String header = JsonCodec.mapper().writeValueAsString(
                    java.util.Map.of("alg", "HS256", "typ", "JWT", "kid", active.id()));
            String headerB64 = b64url(header);
            String payloadB64 = b64url(JsonCodec.mapper().writeValueAsString(claims));
            String signingInput = headerB64 + "." + payloadB64;
            byte[] sig = HmacSigner.newMac(active.secret())
                    .doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            String sigB64 = b64url.encodeToString(sig);
            return signingInput + "." + sigB64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue access token", e);
        }
    }

    /**
     * 校验令牌。注意：这里只做令牌自身的密码学与声明校验；
     * 主体匹配、族代际状态等与请求上下文相关的判定由上层完成。
     */
    public AccessTokenClaims verify(String compact, String expectedIssuer) {
        if (compact == null || compact.isBlank()) {
            throw new RejectException(RejectReason.MISSING_TOKEN, "access token is empty");
        }
        String[] parts = compact.split("\\.", -1);
        // 签名段允许为空（alg=none 的经典形态），以便在 alg 判定处给出 UNSUPPORTED_ALG；
        // 头部与载荷段必须非空，否则结构非法。
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new RejectException(RejectReason.MALFORMED_TOKEN,
                    "token must have three dot-separated segments with non-empty header and payload");
        }

        JsonNode header = decodeJson(parts[0], RejectReason.MALFORMED_TOKEN, "header is not valid JSON");
        String alg = header.path("alg").asText(null);
        if (!ALG.equals(alg)) {
            throw new RejectException(RejectReason.UNSUPPORTED_ALG,
                    "unsupported or missing alg: " + alg);
        }

        String signingInput = parts[0] + "." + parts[1];
        byte[] providedSig;
        try {
            providedSig = b64urlDecoder.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new RejectException(RejectReason.MALFORMED_TOKEN, "signature segment is not base64url");
        }
        String kid = header.path("kid").asText(null);
        SigningKeyRing.VerifyResult signatureResult =
                keyRing.verify(kid, signingInput.getBytes(StandardCharsets.UTF_8), providedSig);
        if (signatureResult == SigningKeyRing.VerifyResult.UNKNOWN_KEY) {
            log.debug("Access token rejected: signed by unknown/removed key kid={}", kid);
            throw new RejectException(RejectReason.UNKNOWN_SIGNING_KEY,
                    "token was signed by a key that is not configured (kid=" + kid + ")");
        }
        if (signatureResult != SigningKeyRing.VerifyResult.VALID) {
            log.debug("Access token rejected: signature verification failed");
            throw new RejectException(RejectReason.BAD_SIGNATURE,
                    "signature does not match (token may have been tampered with)");
        }

        JsonNode payload = decodeJson(parts[1], RejectReason.MALFORMED_TOKEN, "payload is not valid JSON");
        for (String required : REQUIRED_CLAIMS) {
            JsonNode node = payload.get(required);
            if (node == null || node.isNull() || node.isMissingNode()
                    || (node.isTextual() && node.asText().isBlank())) {
                throw new RejectException(RejectReason.MISSING_CLAIMS,
                        "required claim is missing or empty: " + required);
            }
        }

        long now = clock.epochSeconds();
        long exp = payload.get("exp").asLong();
        if (exp <= now) {
            log.debug("Access token rejected: expired at {} (now={})", exp, now);
            throw new RejectException(RejectReason.TOKEN_EXPIRED,
                    "token expired at epoch " + exp + " (now " + now + ")");
        }

        String iss = payload.get("iss").asText();
        if (expectedIssuer != null && !expectedIssuer.equals(iss)) {
            throw new RejectException(RejectReason.TOKEN_ISSUER_MISMATCH,
                    "issuer '" + iss + "' does not match expected '" + expectedIssuer + "'");
        }

        return new AccessTokenClaims(
                iss,
                payload.get("sub").asText(),
                payload.path("aud").asText(null),
                payload.get("jti").asText(),
                payload.get("clientId").asText(),
                payload.get("fam").asText(),
                payload.get("iat").asLong(),
                exp,
                payload.get("gen").asLong(),
                readStringList(payload, "roles"),
                readStringList(payload, "scopes"),
                kid);
    }

    private JsonNode decodeJson(String b64, RejectReason malformedReason, String message) {
        final byte[] raw;
        try {
            raw = b64urlDecoder.decode(b64);
        } catch (IllegalArgumentException e) {
            throw new RejectException(RejectReason.MALFORMED_TOKEN, "segment is not base64url");
        }
        try {
            return JsonCodec.mapper().readTree(raw);
        } catch (Exception e) {
            throw new RejectException(malformedReason, message);
        }
    }

    private static List<String> readStringList(JsonNode payload, String field) {
        JsonNode array = payload.get(field);
        if (array == null || !array.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        array.forEach(n -> {
            if (n.isTextual()) {
                result.add(n.asText());
            }
        });
        return List.copyOf(result);
    }

    private String b64url(String value) {
        return b64url.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
