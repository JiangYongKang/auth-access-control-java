package com.github.highcumontoa.authaccesscontroljava.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 密码/密钥哈希与随机串工具。口令仅以 PBKDF2 哈希形式存在，刷新令牌只存 SHA-256 指纹。
 * 存储格式：pbkdf2$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 derivedKey&gt;
 */
public final class SecretHasher {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int SALT_LENGTH = 16;
    private static final int DERIVED_KEY_LENGTH = 256;
    private static final String PREFIX = "pbkdf2$";

    private SecretHasher() {
    }

    public static String pbkdf2Hash(char[] secret) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] derived = pbkdf2(secret, salt, PBKDF2_ITERATIONS, DERIVED_KEY_LENGTH);
        return PREFIX + PBKDF2_ITERATIONS + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(derived);
    }

    public static boolean pbkdf2Matches(char[] secret, String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) {
            return false;
        }
        String[] parts = stored.substring(PREFIX.length()).split("\\$", -1);
        if (parts.length != 3) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expected = Base64.getDecoder().decode(parts[2]);
            byte[] actual = pbkdf2(secret, salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static byte[] pbkdf2(char[] secret, byte[] salt, int iterations, int keyLengthBits) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(secret, salt, iterations, keyLengthBits);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException("PBKDF2 计算失败", ex);
        }
    }

    /**
     * 刷新令牌的不可逆指纹：只保存指纹，即使状态文件泄露也无法还原令牌。
     */
    public static String sha256Base64(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 计算失败", ex);
        }
    }

    /**
     * 生成 256-bit 随机刷新令牌（URL 安全 Base64）。
     */
    public static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * 生成 128-bit 随机标识。
     */
    public static String randomId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
