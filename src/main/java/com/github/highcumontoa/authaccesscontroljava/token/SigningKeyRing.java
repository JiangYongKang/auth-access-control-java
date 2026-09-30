package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Maskers;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 签名密钥环：管理「可配置多把密钥 + 指定当前签发密钥」，支撑密钥的平滑轮换。
 *
 * <p>两种工作模式：
 * <ul>
 *   <li><b>多密钥模式（推荐）</b>：配置 {@code auth.security.keys.<kid>=<secret>} 与
 *       {@code auth.security.active-key-id=<kid>}。新令牌用 active 密钥签发并在 JWT 头部携带
 *       {@code kid}；验签时按令牌头部 kid 定位配置中的对应密钥。只要旧密钥仍保留在配置里，
 *       由它签发、尚未到期的令牌就能继续通过校验；把旧 kid 从配置中摘掉后，这些令牌立即得到
 *       {@link RejectReason#UNKNOWN_SIGNING_KEY}。</li>
 *   <li><b>兼容单密钥模式</b>：只配置 {@code auth.security.hmac-key}（或两者皆空时用一次性
 *       随机密钥）。签发的令牌头部不含 kid，验签时回退用唯一的/活动密钥校验。</li>
 * </ul>
 *
 * <p>密钥只能来自配置，本类不提供任何把密钥原文写盘的能力；日志只输出 kid 与密钥指纹。
 */
public final class SigningKeyRing {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyRing.class);
    private static final int EPHEMERAL_KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 多密钥模式：kid -> 密钥字节（按配置顺序保留，便于日志可读）。 */
    private final Map<String, byte[]> keys = new LinkedHashMap<>();
    private final String activeKeyId;
    private final boolean ephemeral;

    public SigningKeyRing(AuthProperties.Security security) {
        Map<String, String> configured = security.getKeys();
        boolean hasMulti = configured != null && configured.values().stream()
                .anyMatch(v -> v != null && !v.isBlank());
        String legacy = security.getHmacKey();
        boolean hasLegacy = legacy != null && !legacy.isBlank();

        if (hasMulti && hasLegacy) {
            throw new IllegalStateException(
                    "Ambiguous signing key configuration: auth.security.keys (multi-key rotation) "
                            + "and auth.security.hmac-key (legacy single key) must not be set at the same time");
        }

        if (hasMulti) {
            for (Map.Entry<String, String> e : configured.entrySet()) {
                if (e.getKey() == null || e.getKey().isBlank()) {
                    throw new IllegalStateException("Signing key id (kid) must not be blank");
                }
                String v = e.getValue();
                if (v == null || v.isBlank()) {
                    throw new IllegalStateException(
                            "Signing key for kid '" + e.getKey() + "' must not be blank");
                }
                keys.put(e.getKey(), v.getBytes(StandardCharsets.UTF_8));
            }
            if (keys.isEmpty()) {
                throw new IllegalStateException("auth.security.keys is configured but contains no usable key");
            }
            String active = security.getActiveKeyId();
            if (active == null || active.isBlank()) {
                throw new IllegalStateException(
                        "auth.security.active-key-id is required in multi-key mode");
            }
            if (!keys.containsKey(active)) {
                throw new IllegalStateException(
                        "auth.security.active-key-id '" + active + "' is not present in auth.security.keys");
            }
            this.activeKeyId = active;
            this.ephemeral = false;
            log.info("Signing key ring initialised in MULTI-KEY mode: kids={}, active={}",
                    keys.keySet(), active);
        } else if (hasLegacy) {
            keys.put(null, legacy.getBytes(StandardCharsets.UTF_8));
            this.activeKeyId = null;
            this.ephemeral = false;
            log.info("Signing key ring initialised in LEGACY single-key mode (fp={})",
                    Maskers.fingerprint(legacy));
        } else {
            byte[] random = new byte[EPHEMERAL_KEY_BYTES];
            RANDOM.nextBytes(random);
            keys.put(null, random);
            this.activeKeyId = null;
            this.ephemeral = true;
            log.warn("No signing key configured; generated an EPHEMERAL in-memory key. "
                    + "Tokens will not survive a process restart. Set AUTH_HMAC_KEY or "
                    + "AUTH_SIGNING_KEYS for stable verification.");
        }
    }

    /** 是否为一次性内存密钥（重启后旧令牌必然验签失败）。 */
    public boolean isEphemeral() {
        return ephemeral;
    }

    /** 是否为多密钥轮换模式（多密钥模式下新签发的令牌带 kid）。 */
    public boolean isMultiKey() {
        return activeKeyId != null;
    }

    /** 当前签发密钥的 kid；单密钥/临时模式返回 {@code null}（令牌头部不带 kid）。 */
    public String activeKeyId() {
        return activeKeyId;
    }

    /** 用当前活动密钥签名。 */
    public byte[] signActive(byte[] data) {
        return HmacSigner.newMac(keys.get(activeKeyId)).doFinal(data);
    }

    /**
     * 按令牌头部的 kid 选择密钥验签。
     *
     * @param tokenKid 令牌头部的 kid；{@code null} 表示旧式无 kid 令牌，回退到唯一/活动密钥
     * @return 验签结论：MATCHED / SIGNATURE_MISMATCH / KEY_NOT_FOUND
     */
    public SignatureCheck verify(byte[] data, byte[] signature, String tokenKid) {
        if (signature == null) {
            return SignatureCheck.SIGNATURE_MISMATCH;
        }
        byte[] key = keys.get(tokenKid);
        if (key == null) {
            // 令牌声明了 kid 但配置里没有（或已被摘除）；无 kid 的旧式令牌在单密钥模式下也能取到 key。
            return SignatureCheck.KEY_NOT_FOUND;
        }
        byte[] expected = HmacSigner.newMac(key).doFinal(data);
        return java.security.MessageDigest.isEqual(expected, signature)
                ? SignatureCheck.MATCHED
                : SignatureCheck.SIGNATURE_MISMATCH;
    }

    /** 诊断用：当前配置中的 kid 列表（单密钥模式为空列表），绝不返回密钥本身。 */
    public List<String> configuredKids() {
        return keys.keySet().stream().filter(k -> k != null).toList();
    }

    /** 验签三态结论。 */
    public enum SignatureCheck {
        MATCHED,
        SIGNATURE_MISMATCH,
        KEY_NOT_FOUND
    }
}
