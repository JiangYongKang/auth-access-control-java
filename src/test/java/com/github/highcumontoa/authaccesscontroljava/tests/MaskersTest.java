package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import org.junit.jupiter.api.Test;

class MaskersTest {

    @Test
    void maskTokenNeverContainsFullToken() {
        String token = "eyJhbGciOiJIUzI1NiJ9.payload.signature-part-1234567890";
        String masked = Maskers.maskToken(token);

        assertThat(masked).doesNotContain(token);
        assertThat(masked).contains("len=" + token.length());
        assertThat(masked).contains("fp=");
        // 保留少量前缀用于辨识
        assertThat(masked).startsWith("eyJhbGci");
    }

    @Test
    void maskSecretIsFixedShape() {
        assertThat(Maskers.maskSecret("web-secret")).isEqualTo("******");
        assertThat(Maskers.maskSecret("a-different-secret")).isEqualTo("******");
        assertThat(Maskers.maskSecret(null)).isEqualTo("<none>");
    }

    @Test
    void fingerprintIsStableShortAndOneWay() {
        String fp1 = Maskers.fingerprint("repeatable-token");
        String fp2 = Maskers.fingerprint("repeatable-token");
        String fpOther = Maskers.fingerprint("other-token");

        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).hasSize(12);
        assertThat(fp1).isNotEqualTo(fpOther);
        assertThat(fp1).doesNotContain("repeatable");
    }

    @Test
    void nullTokenIsMaskedAsNone() {
        assertThat(Maskers.maskToken(null)).isEqualTo("<none>");
        assertThat(Maskers.maskToken("")).isEqualTo("<none>");
    }
}
