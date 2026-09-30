package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * HMAC-SHA256 签名器：薄封装，真正的多密钥选择/轮换逻辑在 {@link SigningKeyRing}。
 *
 * <p>密钥来源只有两种，均不落盘：
 * <ol>
 *   <li>配置：多密钥 {@code auth.security.keys} + {@code auth.security.active-key-id}（轮换模式），
 *       或旧式单密钥 {@code auth.security.hmac-key}（兼容模式，推荐改用 AUTH_HMAC_KEY 注入）；</li>
 *   <li>配置缺失时，由 {@link SigningKeyRing} 在进程内存中用 SecureRandom 生成一次性随机密钥，
 *       进程结束即消失——重启后旧令牌必然验签失败，属可解释的预期行为。</li>
 * </ol>
 */
@Component
public class HmacSigner {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private final SigningKeyRing keyRing;

    @Autowired
    public HmacSigner(AuthProperties props) {
        this(new SigningKeyRing(props.getSecurity()));
    }

    public HmacSigner(SigningKeyRing keyRing) {
        this.keyRing = keyRing;
    }

    public SigningKeyRing keyRing() {
        return keyRing;
    }

    public boolean isEphemeral() {
        return keyRing.isEphemeral();
    }

    /** 用当前活动密钥签名。 */
    public byte[] sign(byte[] data) {
        return keyRing.signActive(data);
    }

    /**
     * 旧式无 kid 验签（兼容入口）：按头部无 kid 的令牌处理，回退到唯一/活动密钥。
     * 多密钥模式下应使用 {@link #verifyWithKid(byte[], byte[], String)} 以便区分
     * 「密钥未知/已摘除」与「签名对不上」。
     */
    public boolean verify(byte[] data, byte[] signature) {
        return keyRing.verify(data, signature, null) == SigningKeyRing.SignatureCheck.MATCHED;
    }

    /** 按令牌头部 kid 选择密钥验签，返回可区分的三态结论。 */
    public SigningKeyRing.SignatureCheck verifyWithKid(byte[] data, byte[] signature, String tokenKid) {
        return keyRing.verify(data, signature, tokenKid);
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
