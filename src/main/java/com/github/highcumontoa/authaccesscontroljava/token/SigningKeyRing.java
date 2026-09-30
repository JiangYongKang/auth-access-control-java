package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 多签名密钥环：支持签名密钥的平滑轮换。
 *
 * <p>配置方式（密钥只来自配置，进程内存中保存，绝不写盘）：
 * <ul>
 *   <li>多密钥模式：{@code auth.security.signing-keys.<id>=<secret>}，
 *       并用 {@code auth.security.active-key-id=<id>} 指定当前签发密钥；</li>
 *   <li>兼容模式：仅配置旧的 {@code auth.security.hmac-key}（或环境变量 AUTH_HMAC_KEY）时，
 *       等价于只有一把 id 为 {@link #LEGACY_KEY_ID} 的密钥，且它就是当前密钥；</li>
 *   <li>都未配置时：在内存中用 {@link SecureRandom} 生成一次性随机当前密钥
 *       （重启后旧令牌必然验签失败，仅适合临时调试）。</li>
 * </ul>
 *
 * <p>验签三种结论必须可区分：
 * <ul>
 *   <li>{@link VerifyResult#VALID}：kid 对应密钥存在且签名匹配；</li>
 *   <li>{@link VerifyResult#UNKNOWN_KEY}：kid 为已摘除/从未配置的密钥；</li>
 *   <li>{@link VerifyResult#BAD_SIGNATURE}：kid 对应密钥仍在配置中，但签名对不上。</li>
 * </ul>
 * 为防止「逐个试 kid」式的区分探测，这里仍对两种失败保持相同量级的 HMAC 计算路径。
 */
@Component
public final class SigningKeyRing {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyRing.class);
    private static final int EPHEMERAL_KEY_BYTES = 32;

    /** 旧版单密钥配置与无 kid 头部令牌的兼容密钥 ID。 */
    public static final String LEGACY_KEY_ID = "default";

    /** 验签结论：三种状态必须彼此可区分。 */
    public enum VerifyResult { VALID, UNKNOWN_KEY, BAD_SIGNATURE }

    private final Map<String, byte[]> keys = new LinkedHashMap<>();
    private final String activeKeyId;
    private final boolean ephemeral;
    /** kid 找不到时仍执行一次等长 HMAC 的占位密钥，避免"直接返回"造成可观测时序差异。 */
    private final byte[] timingEqualizer = new byte[EPHEMERAL_KEY_BYTES];

    public SigningKeyRing(AuthProperties props) {
        AuthProperties.Security sec = props.getSecurity();
        Map<String, String> configured = sec.getSigningKeys() == null
                ? Map.of() : sec.getSigningKeys();

        boolean legacyPresent = sec.getHmacKey() != null && !sec.getHmacKey().isBlank();
        if (!configured.isEmpty()) {
            for (Map.Entry<String, String> e : configured.entrySet()) {
                if (e.getKey() == null || e.getKey().isBlank()
                        || e.getValue() == null || e.getValue().isEmpty()) {
                    throw new IllegalStateException(
                            "auth.security.signing-keys contains a blank key id or secret");
                }
                keys.put(e.getKey(), e.getValue().getBytes(StandardCharsets.UTF_8));
            }
            String active = sec.getActiveKeyId();
            if (active == null || active.isBlank()) {
                throw new IllegalStateException(
                        "auth.security.active-key-id must name one of the configured signing keys");
            }
            if (!keys.containsKey(active)) {
                throw new IllegalStateException(
                        "auth.security.active-key-id='" + active + "' is not present in signing-keys "
                                + keys.keySet());
            }
            this.activeKeyId = active;
            this.ephemeral = false;
            log.info("Signing key ring loaded from configuration: keyCount={}, active={}, fingerprints={}",
                    keys.size(), activeKeyId, fingerprints());
        } else if (legacyPresent) {
            keys.put(LEGACY_KEY_ID, sec.getHmacKey().getBytes(StandardCharsets.UTF_8));
            this.activeKeyId = LEGACY_KEY_ID;
            this.ephemeral = false;
            log.info("Single legacy signing key loaded from configuration as kid='{}' (fp={})",
                    LEGACY_KEY_ID, Maskers.fingerprint(sec.getHmacKey()));
        } else {
            byte[] random = new byte[EPHEMERAL_KEY_BYTES];
            new SecureRandom().nextBytes(random);
            keys.put(LEGACY_KEY_ID, random);
            this.activeKeyId = LEGACY_KEY_ID;
            this.ephemeral = true;
            log.warn("No signing key configured; generated an EPHEMERAL in-memory key (kid={}). "
                    + "Tokens will not survive a process restart. Configure auth.security.signing-keys "
                    + "and active-key-id (or AUTH_HMAC_KEY) for stable verification.", LEGACY_KEY_ID);
        }
    }

    private String fingerprints() {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, byte[]> e : keys.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            sb.append(e.getKey()).append('=')
                    .append(Maskers.fingerprint(new String(e.getValue(), StandardCharsets.UTF_8)));
            first = false;
        }
        return sb.append('}').toString();
    }

    public SigningKey activeKey() {
        return new SigningKey(activeKeyId, keys.get(activeKeyId), true);
    }

    /**
     * 用 kid 指定的密钥校验签名。
     *
     * @param kid JWT 头部 kid；为 null（旧令牌没有 kid）时按兼容密钥 {@link #LEGACY_KEY_ID} 处理
     */
    public VerifyResult verify(String kid, byte[] signingInput, byte[] providedSignature) {
        if (providedSignature == null) {
            return VerifyResult.BAD_SIGNATURE;
        }
        String keyId = (kid == null || kid.isBlank()) ? LEGACY_KEY_ID : kid;
        byte[] secret = keys.get(keyId);
        if (secret == null) {
            // 仍执行一次等长 HMAC，避免「找不到 key 直接返回」造成可观测的时序差异。
            HmacSigner.newMac(timingEqualizer).doFinal(signingInput);
            return VerifyResult.UNKNOWN_KEY;
        }
        Mac mac = HmacSigner.newMac(secret);
        byte[] expected = mac.doFinal(signingInput);
        return MessageDigest.isEqual(expected, providedSignature)
                ? VerifyResult.VALID : VerifyResult.BAD_SIGNATURE;
    }

    public boolean isEphemeral() {
        return ephemeral;
    }
}
