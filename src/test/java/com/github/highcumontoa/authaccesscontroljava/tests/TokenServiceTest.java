package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.token.TokenClaims;
import com.github.highcumontoa.authaccesscontroljava.token.TokenRejectReason;
import com.github.highcumontoa.authaccesscontroljava.token.TokenService;
import com.github.highcumontoa.authaccesscontroljava.token.TokenStateStore;
import com.github.highcumontoa.authaccesscontroljava.token.TokenValidationException;

class TokenServiceTest {

    private MutableClock clock;
    private TokenService tokenService;
    private ObjectMapper objectMapper;
    private AuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AuthProperties();
        properties.getToken().setKeyBase64(Base64.getEncoder().encodeToString(new byte[32]));
        properties.getToken().setTtl(Duration.ofMinutes(1));
        clock = new MutableClock(Instant.parse("2026-09-23T00:00:00Z"));
        objectMapper = new ObjectMapper();
        tokenService = new TokenService(properties, clock, new NoopStore(), objectMapper);
    }

    @Test
    void validTokenVerifies() {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of("USER"), List.of("profile:read")));
        TokenClaims claims = tokenService.verify(token);
        assertEquals("alice", claims.subject());
        assertEquals("webapp", claims.clientId());
        assertEquals("local-api", claims.audience());
    }

    @Test
    void expiredTokenRejected() {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        clock.advance(Duration.ofMinutes(2));
        assertEquals(TokenRejectReason.EXPIRED,
                assertThrows(TokenValidationException.class, () -> tokenService.verify(token)).getReason());
    }

    @Test
    void tamperedSignatureRejected() {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        // 翻转签名首字符（保持合法十六进制与长度不变），这是“格式正确但被篡改”
        int dot = token.lastIndexOf('.');
        char original = token.charAt(dot + 1);
        char flipped = original == 'a' ? 'b' : 'a';
        String tampered = token.substring(0, dot + 1) + flipped + token.substring(dot + 2);
        assertEquals(TokenRejectReason.SIGNATURE_INVALID,
                assertThrows(TokenValidationException.class, () -> tokenService.verify(tampered))
                        .getReason());
    }

    @Test
    void tamperedPayloadRejected() throws Exception {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        String[] parts = token.split("\\.");
        ObjectNode payload = (ObjectNode) objectMapper.readTree(
                Base64.getUrlDecoder().decode(parts[0]));
        payload.put("sub", "mallory");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsBytes(payload));
        assertEquals(TokenRejectReason.SIGNATURE_INVALID,
                assertThrows(TokenValidationException.class,
                        () -> tokenService.verify(forgedPayload + "." + parts[1])).getReason());
    }

    @Test
    void issuerMismatchRejected() throws Exception {
        assertEquals(TokenRejectReason.ISSUER_MISMATCH,
                assertThrows(TokenValidationException.class,
                        () -> tokenService.verify(signedTokenWith("iss", "other-issuer"))).getReason());
    }

    @Test
    void audienceMismatchRejected() throws Exception {
        assertEquals(TokenRejectReason.AUDIENCE_MISMATCH,
                assertThrows(TokenValidationException.class,
                        () -> tokenService.verify(signedTokenWith("aud", "other-api"))).getReason());
    }

    @Test
    void missingRequiredClaimRejected() throws Exception {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        String[] parts = token.split("\\.");
        ObjectNode payload = (ObjectNode) objectMapper.readTree(
                Base64.getUrlDecoder().decode(parts[0]));
        payload.remove("jti");
        assertEquals(TokenRejectReason.MISSING_REQUIRED_CLAIM,
                assertThrows(TokenValidationException.class,
                        () -> tokenService.verify(resign(payload))).getReason());
    }

    @Test
    void malformedAndGarbageRejected() {
        assertEquals(TokenRejectReason.MALFORMED,
                assertThrows(TokenValidationException.class, () -> tokenService.verify("")).getReason());
        assertEquals(TokenRejectReason.MALFORMED,
                assertThrows(TokenValidationException.class, () -> tokenService.verify("abc")).getReason());
        assertEquals(TokenRejectReason.MALFORMED,
                assertThrows(TokenValidationException.class, () -> tokenService.verify("abc.")).getReason());
        assertEquals(TokenRejectReason.MALFORMED,
                assertThrows(TokenValidationException.class,
                        () -> tokenService.verify("!!!.@@@")).getReason());
    }

    @Test
    void deniedJtiRejected() {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        String jti = tokenService.verify(token).jti();
        TokenService deniedService = new TokenService(properties, clock, new DenyingStore(jti), objectMapper);
        assertEquals(TokenRejectReason.TOKEN_DENIED,
                assertThrows(TokenValidationException.class, () -> deniedService.verify(token)).getReason());
    }

    private String signedTokenWith(String claim, String value) throws Exception {
        String token = tokenService.issue(new TokenService.TokenClaimsData(
                "alice", "webapp", List.of(), List.of()));
        ObjectNode payload = readPayload(token);
        payload.put(claim, value);
        return resign(payload);
    }

    private ObjectNode readPayload(String token) throws Exception {
        String[] parts = token.split("\\.");
        return (ObjectNode) objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
    }

    /** 用被测服务自身的 HMAC 重新签名，确保失败原因来自声明而非签名。 */
    private String resign(ObjectNode payload) throws Exception {
        String payloadPart = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsBytes(payload));
        Method sign = TokenService.class.getDeclaredMethod("sign", String.class);
        sign.setAccessible(true);
        String sig = (String) sign.invoke(tokenService, payloadPart);
        return payloadPart + "." + sig;
    }

    static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration d) {
            instant = instant.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    static class NoopStore implements TokenStateStore {
        @Override
        public TokenState createFamily(String subject, String clientId, String refreshHash, String refreshJti,
                                       long expiresAtEpochMs, String currentAccessJti,
                                       java.util.List<String> scopes) {
            return new TokenState("f", subject, clientId);
        }

        @Override
        public RotationOutcome rotate(String refreshHash, String clientId, String newRefreshHash,
                                      String newRefreshJti, long newExpiresAtEpochMs, String newAccessJti) {
            return new RotationOutcome("f", "alice", clientId, "ACTIVE", false, java.util.List.of());
        }

        @Override
        public boolean revokeFamily(String refreshHash, String clientId) {
            return true;
        }

        @Override
        public boolean isFamilyRevoked(String familyId) {
            return false;
        }

        @Override
        public String tokenStatus(String refreshHash) {
            return "UNKNOWN";
        }

        @Override
        public boolean isAccessDenied(String jti) {
            return false;
        }
    }

    static class DenyingStore extends NoopStore {
        private final String deniedJti;

        DenyingStore(String deniedJti) {
            this.deniedJti = deniedJti;
        }

        @Override
        public boolean isAccessDenied(String jti) {
            return deniedJti.equals(jti);
        }
    }
}
