package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.AccessTokenService;
import com.github.highcumontoa.authaccesscontroljava.token.HmacSigner;
import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.SigningKeyRing;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccessTokenServiceTest {

    static final String ISSUER = "test-issuer";

    static class FixedClock extends Clock {
        private long seconds;

        FixedClock(long seconds) {
            this.seconds = seconds;
        }

        void advance(long delta) {
            seconds += delta;
        }

        @Override
        public Instant now() {
            return Instant.ofEpochSecond(seconds);
        }
    }

    private FixedClock clock;
    private AccessTokenService service;
    private long now;

    @BeforeEach
    void setUp() {
        now = 1_700_000_000L;
        clock = new FixedClock(now);
        AuthProperties props = new AuthProperties();
        props.getSecurity().setHmacKey("unit-test-hmac-key-0123456789");
        props.getSecurity().setIssuer(ISSUER);
        service = new AccessTokenService(new SigningKeyRing(props), clock);
    }

    private static SigningKeyRing ringWith(String keyId, String secret) {
        AuthProperties props = new AuthProperties();
        props.getSecurity().getSigningKeys().put(keyId, secret);
        props.getSecurity().setActiveKeyId(keyId);
        return new SigningKeyRing(props);
    }

    private AccessTokenClaims claims() {
        return new AccessTokenClaims(ISSUER, "u-alice", "local-resource-api", "jti-1",
                "client-web", "fam-1", now, now + 600, 0L,
                List.of("USER"), List.of("read"), SigningKeyRing.LEGACY_KEY_ID);
    }

    @Test
    void roundTripValidToken() {
        String token = service.issue(claims());
        AccessTokenClaims parsed = service.verify(token, ISSUER);

        assertThat(parsed.sub()).isEqualTo("u-alice");
        assertThat(parsed.fam()).isEqualTo("fam-1");
        assertThat(parsed.scopes()).containsExactly("read");
    }

    @Test
    void expiredTokenIsRejectedWithDistinctReason() {
        String token = service.issue(claims());
        clock.advance(601);

        assertThatThrownBy(() -> service.verify(token, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.TOKEN_EXPIRED));
    }

    @Test
    void tamperedPayloadIsRejectedAsBadSignature() {
        String token = service.issue(claims());
        String[] parts = token.split("\\.");
        // 把 payload 中 alice 替换为 xxxxx（保持长度），签名必然不匹配
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        String tamperedPayload = payload.replace("u-alice", "u-axxxx");
        String tamperedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tamperedPayload.getBytes());
        String tampered = parts[0] + "." + tamperedB64 + "." + parts[2];

        assertThatThrownBy(() -> service.verify(tampered, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.BAD_SIGNATURE));
    }

    @Test
    void tamperedSignatureIsRejectedAsBadSignature() {
        String token = service.issue(claims());
        String[] parts = token.split("\\.");
        char last = parts[2].charAt(parts[2].length() - 1);
        String flipped = parts[2].substring(0, parts[2].length() - 1) + (last == 'A' ? 'B' : 'A');

        assertThatThrownBy(() -> service.verify(parts[0] + "." + parts[1] + "." + flipped, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.BAD_SIGNATURE));
    }

    @Test
    void unsignedNoneAlgIsRejectedAsUnsupportedAlg() {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{}".getBytes());
        String noneToken = header + "." + payload + ".";

        assertThatThrownBy(() -> service.verify(noneToken, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.UNSUPPORTED_ALG));
    }

    @Test
    void wrongAlgNameIsRejected() {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{}".getBytes());
        String token = header + "." + payload + "." + "x".repeat(32);

        assertThatThrownBy(() -> service.verify(token, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.UNSUPPORTED_ALG));
    }

    @Test
    void malformedStructuresAreRejected() {
        assertThatThrownBy(() -> service.verify("only-one-segment", ISSUER))
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.MALFORMED_TOKEN);
        assertThatThrownBy(() -> service.verify("a.b", ISSUER))
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.MALFORMED_TOKEN);
        assertThatThrownBy(() -> service.verify("a..c", ISSUER))
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.MALFORMED_TOKEN);
        assertThatThrownBy(() -> service.verify("", ISSUER))
                .extracting(ex -> ((RejectException) ex).reason())
                .isEqualTo(RejectReason.MISSING_TOKEN);
    }

    @Test
    void missingRequiredClaimIsRejected() throws Exception {
        // 构造一个签名合法但缺少 fam 声明的令牌（直接用当前密钥手动签发）
        AuthProperties props = new AuthProperties();
        props.getSecurity().setHmacKey("unit-test-hmac-key-0123456789");
        SigningKeyRing signerRing = new SigningKeyRing(props);

        String headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        var incomplete = new java.util.LinkedHashMap<String, Object>();
        incomplete.put("iss", ISSUER);
        incomplete.put("sub", "u-alice");
        incomplete.put("jti", "j");
        incomplete.put("iat", now);
        incomplete.put("exp", now + 600);
        incomplete.put("clientId", "client-web");
        incomplete.put("gen", 0);
        // 故意不包含 fam
        String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JsonCodec.mapper().writeValueAsBytes(incomplete));
        String input = headerB64 + "." + payloadB64;
        String sig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(HmacSigner.newMac(signerRing.activeKey().secret())
                        .doFinal(input.getBytes()));
        String token = input + "." + sig;

        assertThatThrownBy(() -> service.verify(token, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.MISSING_CLAIMS));
    }

    @Test
    void issuerMismatchIsRejectedDistinctly() {
        String token = service.issue(claims());
        assertThatThrownBy(() -> service.verify(token, "another-issuer"))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.TOKEN_ISSUER_MISMATCH));
    }

    @Test
    void tokenSignedByAnotherKeyIsRejectedAsBadSignature() {
        // 两把密钥都保留在环中：kid 能找到密钥，但签名是另一把密钥算出来的 → bad_signature。
        AuthProperties ringProps = new AuthProperties();
        ringProps.getSecurity().getSigningKeys().put("k1", "unit-test-hmac-key-0123456789");
        // 同样叫 k2，但密钥值与签发方不同：kid 可识别，签名却对不上。
        ringProps.getSecurity().getSigningKeys().put("k2", "yet-another-secret-value-777");
        ringProps.getSecurity().setActiveKeyId("k1");
        AccessTokenService ringService = new AccessTokenService(new SigningKeyRing(ringProps), clock);

        AuthProperties foreignProps = new AuthProperties();
        foreignProps.getSecurity().getSigningKeys().put("k2", "a-totally-different-key-999");
        foreignProps.getSecurity().setActiveKeyId("k2");
        AccessTokenService foreignService = new AccessTokenService(new SigningKeyRing(foreignProps), clock);
        String foreignToken = foreignService.issue(claims());

        assertThatThrownBy(() -> ringService.verify(foreignToken, ISSUER))
                .isInstanceOfSatisfying(RejectException.class,
                        ex -> assertThat(ex.reason()).isEqualTo(RejectReason.BAD_SIGNATURE));
    }
}
