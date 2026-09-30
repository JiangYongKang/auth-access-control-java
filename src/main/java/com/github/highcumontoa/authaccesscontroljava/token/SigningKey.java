package com.github.highcumontoa.authaccesscontroljava.token;

/**
 * 签名密钥环中的一把 HMAC 密钥。
 *
 * <p>{@code id} 会作为 JWT 头部 {@code kid} 出现（不是秘密）；
 * {@code secret} 只存在于进程内存中，来自配置/环境变量，不允许写入任何磁盘文件。
 */
public record SigningKey(String id, byte[] secret, boolean active) {
}
