package com.github.highcumontoa.authaccesscontroljava.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.security.SensitiveLog;

/**
 * 访问令牌签发与校验（自包含 HMAC-SHA256 令牌，不依赖任何外部服务）。
 *
 * <p>令牌格式：base64url(payloadJSON).base64url(hmac)。payload 至少包含
 * jti/sub/cid/iss/aud/roles/scopes/iat/exp，缺少任一必需声明即拒绝。</p>
 */
@Component
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final List<String> REQUIRED_CLAIMS =
            List.of("jti", "sub", "cid", "iss", "aud", "roles", "scopes", "iat", "exp");

    private final AuthProperties properties;
    private final Clock clock;
    private final TokenStateStore stateStore;
    private final ObjectMapper objectMapper;
    private final byte[] signingKey;

    public TokenService(AuthProperties properties, Clock clock, TokenStateStore stateStore,
                        ObjectMapper objectMapper) {
        this.properties = properties;
        this.clock = clock;
        this.stateStore = stateStore;
        this.objectMapper = objectMapper;
        String keyBase64 = properties.getToken().getKeyBase64();
        if (keyBase64 == null || keyBase64.isBlank()) {
            throw new IllegalStateException("auth.token.key-base64 未配置：签名密钥只能来自配置/环境变量");
        }
        try {
            this.signingKey = Base64.getDecoder().decode(keyBase64);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("auth.token.key-base64 不是合法的 Base64", ex);
        }
        if (this.signingKey.length < 32) {
            throw new IllegalStateException("签名密钥长度不足，至少需要 256 bit");
        }
    }

    /**
     * 签发新访问令牌（随机 jti）。
     */
    public String issue(TokenClaimsData data) {
        return issue(data, java.util.UUID.randomUUID().toString().replace("-", ""));
    }

    /**
     * 以指定 jti 签发访问令牌（轮换时由调用方预先登记到令牌家族）。
     */
    public String issue(TokenClaimsData data, String jti) {
        long now = clock.instant().toEpochMilli();
        long exp = now + properties.getToken().getTtl().toMillis();
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("jti", jti);
        payload.put("sub", data.subject());
        payload.put("cid", data.clientId());
        payload.put("iss", properties.getToken().getIssuer());
        payload.put("aud", properties.getToken().getAudience());
        payload.putPOJO("roles", data.roles());
        payload.putPOJO("scopes", data.scopes());
        payload.put("iat", now);
        payload.put("exp", exp);
        byte[] payloadBytes;
        try {
            payloadBytes = objectMapper.writeValueAsBytes(payload);
        } catch (Exception ex) {
            throw new IllegalStateException("令牌序列化失败", ex);
        }
        String payloadPart = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadBytes);
        String signaturePart = sign(payloadPart);
        log.info("签发访问令牌: sub={}, cid={}, jti={}, exp={}", data.subject(), data.clientId(),
                payload.get("jti").asText(), exp);
        return payloadPart + "." + signaturePart;
    }

    /**
     * 校验访问令牌：过期、篡改、签发主体不符、缺少必需声明等均抛出可区分异常，
     * 并额外检查轮换/撤销后的 jti 拒绝清单。
     */
    public TokenClaims verify(String compact) {
        if (compact == null || compact.isBlank()) {
            throw reject(TokenRejectReason.MALFORMED, null);
        }
        int dot = compact.lastIndexOf('.');
        if (dot <= 0 || dot == compact.length() - 1) {
            throw reject(TokenRejectReason.MALFORMED, null);
        }
        String payloadPart = compact.substring(0, dot);
        String signaturePart = compact.substring(dot + 1);

        // 1) 签名必须是合法十六进制且与 HMAC 匹配（防篡改）
        try {
            HexFormat.of().parseHex(signaturePart);
        } catch (IllegalArgumentException ex) {
            throw reject(TokenRejectReason.MALFORMED, ex);
        }
        String expectedSignature;
        try {
            expectedSignature = sign(payloadPart);
        } catch (IllegalStateException ex) {
            throw reject(TokenRejectReason.MALFORMED, ex);
        }
        if (!constantTimeEquals(expectedSignature, signaturePart)) {
            throw reject(TokenRejectReason.SIGNATURE_INVALID, null);
        }

        // 2) payload 必须可解析
        JsonNode payload;
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(payloadPart);
            payload = objectMapper.readTree(payloadBytes);
        } catch (Exception ex) {
            throw reject(TokenRejectReason.MALFORMED, ex);
        }
        if (payload == null || !payload.isObject()) {
            throw reject(TokenRejectReason.MALFORMED, null);
        }

        // 3) 必需声明齐全
        for (String claim : REQUIRED_CLAIMS) {
            JsonNode node = payload.get(claim);
            if (node == null || node.isNull()
                    || (node.isTextual() && node.asText().isBlank())) {
                throw reject(TokenRejectReason.MISSING_REQUIRED_CLAIM, null, claim);
            }
        }

        String issuer = payload.get("iss").asText();
        String audience = payload.get("aud").asText();

        // 4) 签发主体（issuer / audience）必须与当前服务一致
        if (!properties.getToken().getIssuer().equals(issuer)) {
            throw reject(TokenRejectReason.ISSUER_MISMATCH, null, issuer);
        }
        if (!properties.getToken().getAudience().equals(audience)) {
            throw reject(TokenRejectReason.AUDIENCE_MISMATCH, null, audience);
        }

        // 5) 必须未过期
        long now = clock.instant().toEpochMilli();
        long exp = payload.get("exp").asLong(0L);
        long iat = payload.get("iat").asLong(0L);
        if (exp <= now || iat <= 0) {
            throw reject(TokenRejectReason.EXPIRED, null, String.valueOf(exp));
        }

        TokenClaims claims = new TokenClaims(
                payload.get("jti").asText(),
                payload.get("sub").asText(),
                payload.get("cid").asText(),
                issuer,
                audience,
                readStringList(payload.get("roles")),
                readStringList(payload.get("scopes")),
                iat,
                exp);

        // 6) 轮换或撤销后，旧访问令牌的 jti 进入拒绝清单，立即失效
        if (stateStore.isAccessDenied(claims.jti())) {
            throw reject(TokenRejectReason.TOKEN_DENIED, null, claims.jti());
        }
        log.debug("访问令牌校验通过: sub={}, cid={}, jti={}", claims.subject(), claims.clientId(),
                claims.jti());
        return claims;
    }

    private String sign(String payloadPart) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            byte[] raw = mac.doFinal(payloadPart.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(raw);
        } catch (Exception ex) {
            throw new IllegalStateException("HMAC 计算失败", ex);
        }
    }

    private static List<String> readStringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        var result = new java.util.ArrayList<String>();
        node.forEach(item -> result.add(item.asText()));
        return List.copyOf(result);
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(x, y);
    }

    private TokenValidationException reject(TokenRejectReason reason, Throwable cause, String... evidence) {
        log.warn("访问令牌被拒绝: reason={}, evidence={}", reason,
                evidence.length == 0 ? "-" : SensitiveLog.mask(evidence[0]));
        return cause == null
                ? new TokenValidationException(reason)
                : new TokenValidationException(reason, cause);
    }

    public record TokenClaimsData(String subject, String clientId, List<String> roles,
                                  List<String> scopes) {
    }
}
