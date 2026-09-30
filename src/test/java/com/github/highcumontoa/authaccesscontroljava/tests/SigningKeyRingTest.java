package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.token.HmacSigner;
import com.github.highcumontoa.authaccesscontroljava.token.SigningKeyRing;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SigningKeyRingTest {

    private static AuthProperties multiProps(String active, String... kv) {
        AuthProperties props = new AuthProperties();
        for (int i = 0; i < kv.length; i += 2) {
            props.getSecurity().getSigningKeys().put(kv[i], kv[i + 1]);
        }
        props.getSecurity().setActiveKeyId(active);
        return props;
    }

    @Test
    void legacySingleKeyIsExposedAsDefaultKid() {
        AuthProperties props = new AuthProperties();
        props.getSecurity().setHmacKey("the-only-secret");
        SigningKeyRing ring = new SigningKeyRing(props);

        assertThat(ring.activeKey().id()).isEqualTo(SigningKeyRing.LEGACY_KEY_ID);
        assertThat(ring.isEphemeral()).isFalse();

        byte[] sig = HmacSigner.newMac(ring.activeKey().secret()).doFinal("data".getBytes());
        // 旧令牌没有 kid（null）：按 default 兼容验签。
        assertThat(ring.verify(null, "data".getBytes(StandardCharsets.UTF_8), sig))
                .isEqualTo(SigningKeyRing.VerifyResult.VALID);
    }

    @Test
    void activeKeyIsUsedForSigningAndOldKeyStillVerifies() {
        SigningKeyRing ring = new SigningKeyRing(
                multiProps("new", "old", "old-secret", "new", "new-secret"));
        assertThat(ring.activeKey().id()).isEqualTo("new");

        byte[] data = "signing-input".getBytes(StandardCharsets.UTF_8);
        byte[] oldSig = HmacSigner.newMac("old-secret".getBytes(StandardCharsets.UTF_8)).doFinal(data);
        byte[] newSig = HmacSigner.newMac("new-secret".getBytes(StandardCharsets.UTF_8)).doFinal(data);

        assertThat(ring.verify("old", data, oldSig)).isEqualTo(SigningKeyRing.VerifyResult.VALID);
        assertThat(ring.verify("new", data, newSig)).isEqualTo(SigningKeyRing.VerifyResult.VALID);
        // kid 仍在配置中，但签名对不上：bad_signature，而不是 unknown_key。
        assertThat(ring.verify("new", data, oldSig)).isEqualTo(SigningKeyRing.VerifyResult.BAD_SIGNATURE);
        // kid 已从配置摘除/从未配置：unknown_signing_key，必须与 bad_signature 分开。
        assertThat(ring.verify("removed", data, oldSig))
                .isEqualTo(SigningKeyRing.VerifyResult.UNKNOWN_KEY);
    }

    @Test
    void removedKeyStopsVerifyingWhileRemainingKeysStillDo() {
        // 轮换前：old + new 都在
        SigningKeyRing before = new SigningKeyRing(
                multiProps("new", "old", "old-secret", "new", "new-secret"));
        byte[] data = "x".getBytes(StandardCharsets.UTF_8);
        byte[] oldSig = HmacSigner.newMac("old-secret".getBytes(StandardCharsets.UTF_8)).doFinal(data);
        assertThat(before.verify("old", data, oldSig)).isEqualTo(SigningKeyRing.VerifyResult.VALID);

        // 运维摘掉 old 后（模拟新进程载入新配置）
        SigningKeyRing after = new SigningKeyRing(multiProps("new", "new", "new-secret"));
        assertThat(after.verify("old", data, oldSig)).isEqualTo(SigningKeyRing.VerifyResult.UNKNOWN_KEY);
    }

    @Test
    void activeKeyIdMustExist() {
        assertThatThrownBy(() -> new SigningKeyRing(multiProps("missing", "a", "secret-a")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("active-key-id");
    }

    @Test
    void noConfiguredKeyProducesEphemeralDefaultKey() {
        SigningKeyRing ring = new SigningKeyRing(new AuthProperties());
        assertThat(ring.isEphemeral()).isTrue();
        assertThat(ring.activeKey().id()).isEqualTo(SigningKeyRing.LEGACY_KEY_ID);
    }
}
