package com.github.highcumontoa.authaccesscontroljava.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 日志脱敏工具。所有可能出现在日志里的敏感材料（访问令牌、刷新令牌、客户端密钥、口令）
 * 都必须经由此类处理：只允许输出固定前缀或不可逆指纹，绝不允许输出原文。
 */
public final class Maskers {

    /** 日志中允许保留的令牌明文前缀长度（JWT/刷新令牌前缀不含任何签名信息）。 */
    private static final int TOKEN_PREFIX_KEEP = 8;

    private Maskers() {
    }

    /**
     * 对令牌脱敏：保留少量前缀用于辨识类型，附带长度与短指纹，中间与尾部全部遮蔽。
     * 例如 {@code abcdefgh...(len=180,fp=9f86d081884c)}。
     */
    public static String maskToken(String token) {
        if (token == null || token.isEmpty()) {
            return "<none>";
        }
        String prefix = token.length() <= TOKEN_PREFIX_KEEP
                ? "****"
                : token.substring(0, TOKEN_PREFIX_KEEP) + "...";
        return prefix + "(len=" + token.length() + ",fp=" + fingerprint(token) + ")";
    }

    /** 对客户端密钥/用户口令脱敏：固定输出，不泄露长度与任何字符。 */
    public static String maskSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "<none>";
        }
        return "******";
    }

    /**
     * 稳定的短指纹（SHA-256 前 12 位 hex），用于跨日志关联同一令牌/密钥，
     * 单向不可逆，无法据此还原原文。
     */
    public static String fingerprint(String value) {
        if (value == null) {
            return "<none>";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 6 && i < digest.length; i++) {
                sb.append(String.format("%02x", digest[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
