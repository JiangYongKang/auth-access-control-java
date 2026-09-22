package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.github.highcumontoa.authaccesscontroljava.security.SensitiveLog;

class SensitiveLogTest {

    @Test
    void maskHidesTokenBody() {
        String secret = "eyJhbGciOiJIUzI1NiJ9.verylongtokenvalue123456";
        String masked = SensitiveLog.mask(secret);
        assertFalse(masked.contains("verylongtokenvalue"), "掩码后不得包含令牌主体");
        assertTrue(masked.startsWith(secret.substring(0, 4)));
        assertTrue(masked.contains("*"));
    }

    @Test
    void maskNullOrShort() {
        assertTrue(SensitiveLog.mask(null).contains("*"));
        assertTrue(SensitiveLog.mask("abc").contains("*"));
    }
}
