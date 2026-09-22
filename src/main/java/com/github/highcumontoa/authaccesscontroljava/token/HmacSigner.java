package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * HMAC-SHA256 签名器。
 *
 * <p>密钥来源只有两种，均不落盘：
 * <ol>
 *   <li>配置 {@code auth.security.hmac-key}（生产应通过环境变量 AUTH_HMAC_KEY 注入）；</li>
 *   <li>配置缺失时，在进程内存中用 {@link SecureRandom} 生成一次性随机密钥，
 *       进程结束即消失——重启后旧令牌必然验签失败，属可解释的预期行为。</li>
 * </ol>
 */
@Component
public class HmacSigner {

    private static final Logger log = LoggerFactory.getLogger(HmacSigner.class);
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int EPHEMERAL_KEY_BYTES = 32;

    private final byte[] key;
    private final boolean ephemeral;

    public HmacSigner(AuthProperties props) {
        String configured = props.getSecurity().getHmacKey();
        if (configured != null && !configured.isBlank()) {
            this.key = configured.getBytes(StandardCharsets.UTF_8);
            this.ephemeral = false;
            log.info("HMAC signing key loaded from configuration (length={}, fp={})",
                    key.length, com.github.highcumontoa.authaccesscontroljava.support.Maskers.fingerprint(configured));
        } else {
            this.key = new byte[EPHEMERAL_KEY_BYTES];
            new SecureRandom().nextBytes(this.key);
            this.ephemeral = true;
            log.warn("auth.security.hmac-key is not configured; generated an EPHEMERAL in-memory key. "
                    + "Tokens will not survive a process restart. Set AUTH_HMAC_KEY for stable verification.");
        }
    }

    public boolean isEphemeral() {
        return ephemeral;
    }

    public byte[] sign(byte[] data) {
        return newMac(key).doFinal(data);
    }

    /** 常量时间比较，避免签名比对的计时侧信道。 */
    public boolean verify(byte[] data, byte[] signature) {
        if (signature == null) {
            return false;
        }
        byte[] expected = sign(data);
        return MessageDigest.isEqual(expected, signature);
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
