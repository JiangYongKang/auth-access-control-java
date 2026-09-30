package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.HmacSigner;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.SigningKeyRing;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 密钥平滑轮换：多把密钥并存 + 指定当前签发密钥；旧密钥保留则旧令牌继续可用，摘除则立即失效，
 * 且「密钥未知/已摘除」与「签名对不上」是两个不同的拒绝结论。
 */
class SigningKeyRotationTest {

    static final String ISSUER = "rot-issuer";

    static class FixedClock extends Clock {
        private final long seconds;
        FixedClock(long seconds) { this.seconds = seconds; }
        @Override public Instant now() { return Instant.ofEpochSecond(seconds); }
    }

    private final long now = 1_700_000_000L;
    private final Clock clock = new FixedClock(now);

    private AuthProperties multiKeyProps(String active, Map<String, String> keys) {
        AuthProperties props = new AuthProperties();
        props.getSecurity().setIssuer(ISSUER);
        props.getSecurity().setKeys(new LinkedHashMap<>(keys));
        props.getSecurity().setActiveKeyId(active);
        return props;
    }

    private AccessTokenService serviceFor(AuthProperties props) {
        return new AccessTokenService(new HmacSigner(props), clock);
    }

    private AccessTokenClaims claims() {
        return new AccessTokenClaims(ISSUER, "u-alice", "local-resource-api", "jti-rot",
                "client-web", "fam-rot", now, now + 600, 0L,
                List.of("USER"), List.of("read"));
    }

    @Test
    void issuedTokenCarriesActiveKidInHeader() {
        AuthProperties props = multiKeyProps("k2",
                Map.of("k1", "old-secret-key", "k2", "new-secret-key"));
        AccessTokenService service = serviceFor(props);

        String token = service.issue(claims());
        String header = new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        assertThat(header).contains("\"kid\"").contains("k2");
        // 仍可正常验签
        assertThat(service.verify(token, ISSUER).sub()).isEqualTo("u-alice");
    }

    @Test
    void oldKeyStillAcceptedWhileConfiguredAfterRotation() {
        // 阶段 1：active=k1，签发旧令牌
        AccessTokenService phase1 = serviceFor(multiKeyProps("k1",
                Map.of("k1", "secret-one", "k2", "secret-two")));
        String oldToken = phase1.issue(claims());

        // 阶段 2：轮换 active 到 k2，但配置里仍保留 k1 -> 旧令牌继续通过，新令牌走 k2
        AccessTokenService phase2 = serviceFor(multiKeyProps("k2",
                Map.of("k1", "secret-one", "k2", "secret-two")));
        assertThat(phase2.verify(oldToken, ISSUER).sub()).isEqualTo("u-alice");

        String newToken = phase2.issue(claims());
        String newHeader = new String(Base64.getUrlDecoder().decode(newToken.split("\\.")[0]));
        assertThat(newHeader).contains("k2");
        assertThat(phase2.verify(newToken, ISSUER).sub()).isEqualTo("u-alice");
    }

    @Test
    void removingOldKeyImmediatelyInvalidatesItsTokensWithUnknownKey() {
        AccessTokenService phase1 = serviceFor(multiKeyProps("k1",
                Map.of("k1", "secret-one", "k2", "secret-two")));
        String oldToken = phase1.issue(claims());

        // 阶段 3：旧密钥 k1 被摘掉，只剩 k2
        AccessTokenService phase3 = serviceFor(multiKeyProps("k2", Map.of("k2", "secret-two")));
        assertThatThrownBy(() -> phase3.verify(oldToken, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.UNKNOWN_SIGNING_KEY));

        // k2 签发的新令牌不受影响
        assertThat(phase3.verify(phase3.issue(claims()), ISSUER).sub()).isEqualTo("u-alice");
    }

    @Test
    void tamperedSignatureIsBadSignatureNotUnknownKey() {
        AuthProperties props = multiKeyProps("k1",
                Map.of("k1", "secret-one", "k2", "secret-two"));
        AccessTokenService service = serviceFor(props);
        String token = service.issue(claims());
        String[] parts = token.split("\\.");
        char last = parts[2].charAt(parts[2].length() - 1);
        String flipped = parts[2].substring(0, parts[2].length() - 1) + (last == 'A' ? 'B' : 'A');
        String tampered = parts[0] + "." + parts[1] + "." + flipped;

        // kid 仍然认识，但 HMAC 对不上 -> bad_signature，而不是 unknown_signing_key
        assertThatThrownBy(() -> service.verify(tampered, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.BAD_SIGNATURE));
    }

    @Test
    void foreignKeyTokenIsUnknownSigningKeyWhenKidNotConfigured() {
        AccessTokenService issuer = serviceFor(multiKeyProps("k9", Map.of("k9", "foreign-secret")));
        String foreign = issuer.issue(claims());

        AccessTokenService verifier = serviceFor(multiKeyProps("k1", Map.of("k1", "secret-one")));
        assertThatThrownBy(() -> verifier.verify(foreign, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.UNKNOWN_SIGNING_KEY));
    }

    @Test
    void invalidMultiKeyConfigurationFailsFast() {
        // active-key-id 不在 keys 中
        AuthProperties badActive = multiKeyProps("nope", Map.of("k1", "secret-one"));
        assertThatThrownBy(() -> new SigningKeyRing(badActive.getSecurity()))
                .isInstanceOf(IllegalStateException.class);

        // 多密钥与旧单密钥同时配置 -> 拒绝二义性
        AuthProperties ambiguous = multiKeyProps("k1", Map.of("k1", "secret-one"));
        ambiguous.getSecurity().setHmacKey("legacy-also-set");
        assertThatThrownBy(() -> new SigningKeyRing(ambiguous.getSecurity()))
                .isInstanceOf(IllegalStateException.class);
    }
}
