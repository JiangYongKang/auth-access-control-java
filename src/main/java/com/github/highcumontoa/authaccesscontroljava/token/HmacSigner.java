package com.github.highcumontoa.authaccesscontroljava.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 / SHA-256 静态工具。
 *
 * <p>历史上本类还负责持有唯一的签名密钥；多密钥平滑轮换上线后，密钥的持有与选择统一由
 * {@link SigningKeyRing} 完成（密钥仅来自配置、只存在于内存、不落盘），
 * 这里只保留无状态的算法辅助方法。
 */
public final class HmacSigner {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private HmacSigner() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static Mac newMac(byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize HMAC-SHA256", e);
        }
    }
}
