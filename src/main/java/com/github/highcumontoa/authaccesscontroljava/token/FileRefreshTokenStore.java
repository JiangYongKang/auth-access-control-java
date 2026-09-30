package com.github.highcumontoa.authaccesscontroljava.token;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.support.JsonCodec;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

/**
 * 基于本地 JSON 文件的刷新令牌族存储。
 *
 * <p>关键性质：
 * <ul>
 *   <li>所有变更方法均在同一把锁内完成"检查—变更—落盘"，因此并发/重复使用同一刷新令牌时，
 *       全进程最多只有一次 SUCCESS，其余线程看到的一定是旧哈希，得到 REPLAYED。</li>
 *   <li>落盘只写 {@code currentTokenHash}（SHA-256），刷新令牌原文从不出现在磁盘上。</li>
 *   <li>每次落盘采用"写临时文件 + 原子 move"，避免半写文件；进程重启后重新加载，
 *       撤销（revoked）等结论保持一致。</li>
 *   <li>已撤销族不会被清理删除，保证重启后仍然给出 REVOKED 而不是退化为"未知"。</li>
 * </ul>
 */
@Repository
public class FileRefreshTokenStore implements RefreshTokenStore {

    private static final Logger log = LoggerFactory.getLogger(FileRefreshTokenStore.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    /** lastUsedAt 这类非关键时间戳的落盘节流窗口（秒）。 */
    private static final long TOUCH_FLUSH_INTERVAL_SECONDS = 5;

    private final Path stateFile;
    private final Clock clock;
    private final Map<String, RefreshFamily> families = new HashMap<>();
    private long lastTouchFlushAt = Long.MIN_VALUE;

    public FileRefreshTokenStore(AuthProperties props, Clock clock) {
        this.stateFile = Path.of(props.getToken().getStateFile());
        this.clock = clock;
        load();
    }

    private void load() {
        if (!Files.exists(stateFile)) {
            log.info("Refresh token state file does not exist yet, starting empty: {}", stateFile.toAbsolutePath());
            return;
        }
        try {
            List<RefreshFamily> loaded = JsonCodec.mapper().readValue(
                    Files.readAllBytes(stateFile), new TypeReference<List<RefreshFamily>>() {
                    });
            for (RefreshFamily family : loaded) {
                families.put(family.getFamilyId(), family);
            }
            log.info("Loaded {} refresh token families from {}", families.size(), stateFile.toAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Refresh token state file exists but cannot be parsed: " + stateFile.toAbsolutePath(), e);
        }
    }

    private void persistLocked() {
        try {
            Path parent = stateFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = stateFile.resolveSibling(stateFile.getFileName() + ".tmp");
            byte[] json = JsonCodec.mapper().writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(List.copyOf(families.values()));
            Files.write(tmp, json);
            try {
                Files.move(tmp, stateFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicNotSupported) {
                Files.move(tmp, stateFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to persist refresh token state to " + stateFile, e);
        }
    }

    @Override
    public synchronized StoredToken create(String subject, String clientId, long ttlSeconds,
                                          java.util.List<String> roles, java.util.List<String> scopes) {
        String familyId = java.util.UUID.randomUUID().toString();
        String rawToken = mintRawToken(familyId);
        long now = clock.epochSeconds();

        RefreshFamily family = new RefreshFamily();
        family.setFamilyId(familyId);
        family.setSubject(subject);
        family.setClientId(clientId);
        family.setGeneration(0L);
        family.setCurrentTokenHash(hashToken(rawToken));
        family.setIssuedAt(now);
        family.setExpiresAt(now + ttlSeconds);
        family.setRevoked(false);
        family.setLastUsedAt(now);
        family.setLogoutReason(com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason.NONE);
        family.setRoles(java.util.List.copyOf(roles));
        family.setScopes(java.util.List.copyOf(scopes));
        families.put(familyId, family);
        persistLocked();
        log.info("Refresh family created: family={}, subject={}, client={}, ttl={}s",
                familyId, subject, clientId, ttlSeconds);
        return new StoredToken(rawToken, familyId, 0L);
    }

    @Override
    public synchronized RotationResult consume(String rawRefreshToken, String clientId) {
        String familyId = extractFamilyId(rawRefreshToken);
        if (familyId == null) {
            return new RotationResult(RotationOutcome.UNKNOWN, null, null);
        }
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            log.info("Refresh rejected: family unknown: token={}",
                    com.github.highcumontoa.authaccesscontroljava.support.Maskers.maskToken(rawRefreshToken));
            return new RotationResult(RotationOutcome.UNKNOWN, null, null);
        }
        if (clientId != null && !clientId.equals(family.getClientId())) {
            log.info("Refresh rejected: client mismatch, family={}, requestClient={}",
                    familyId, clientId);
            return new RotationResult(RotationOutcome.CLIENT_MISMATCH, family, null);
        }
        if (family.isRevoked()) {
            log.info("Refresh rejected: family revoked, family={}, reason={}",
                    familyId, family.getRevokeReason());
            return new RotationResult(RotationOutcome.REVOKED, family, null);
        }
        long now = clock.epochSeconds();
        if (family.isExpiredAt(now)) {
            log.info("Refresh rejected: family expired, family={}, expiredAt={}, now={}",
                    familyId, family.getExpiresAt(), now);
            return new RotationResult(RotationOutcome.EXPIRED, family, null);
        }
        if (!hashToken(rawRefreshToken).equals(family.getCurrentTokenHash())) {
            // 哈希不匹配：族存在且未撤销，但该令牌不是"当前"令牌——必为重放/并发重复使用。
            log.warn("Refresh rejected: token replay suspected, family={}, currentGen={}",
                    familyId, family.getGeneration());
            return new RotationResult(RotationOutcome.REPLAYED, family, null);
        }

        // 全部检查通过：在同一把锁内立即轮换，旧哈希被覆盖，随后到达的任何重复请求都只能 REPLAYED。
        String nextRaw = mintRawToken(familyId);
        family.setCurrentTokenHash(hashToken(nextRaw));
        family.setGeneration(family.getGeneration() + 1);
        family.setLastUsedAt(clock.epochSeconds());
        persistLocked();
        log.info("Refresh rotated successfully: family={}, newGen={}", familyId, family.getGeneration());
        return new RotationResult(RotationOutcome.SUCCESS, family,
                new StoredToken(nextRaw, familyId, family.getGeneration()));
    }

    @Override
    public synchronized void revoke(String familyId, String reason) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            log.info("Revoke requested for unknown family: {}", familyId);
            return;
        }
        if (!family.isRevoked()) {
            family.setRevoked(true);
            family.setRevokeReason(reason == null ? "explicit_revoke" : reason);
            family.setLogoutReason(com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason.TOKEN_REVOKED);
            persistLocked();
            log.info("Refresh family revoked: family={}, reason={}", familyId, family.getRevokeReason());
        }
    }

    @Override
    public synchronized Optional<RefreshFamily> findByFamilyId(String familyId) {
        return Optional.ofNullable(families.get(familyId));
    }

    @Override
    public synchronized FamilyStatus familyStatus(String familyId, long generation) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            return FamilyStatus.UNKNOWN;
        }
        if (family.isRevoked()) {
            // 区分"会话被注销"与"令牌/族被撤销"：二者在校验错误码与自检原因上必须分开。
            return switch (family.getLogoutReason()) {
                case SESSION_REVOKED, ALL_SESSIONS_REVOKED -> FamilyStatus.LOGGED_OUT;
                default -> FamilyStatus.REVOKED;
            };
        }
        if (family.isExpiredAt(clock.epochSeconds())) {
            // 族已过期等同于状态不可再确认，按"非当前"处理。
            return FamilyStatus.UNKNOWN;
        }
        return family.getGeneration() == generation
                ? FamilyStatus.ACTIVE_CURRENT
                : FamilyStatus.ACTIVE_STALE;
    }

    @Override
    public synchronized List<RefreshFamily> listBySubject(String subject) {
        List<RefreshFamily> result = new java.util.ArrayList<>();
        for (RefreshFamily family : families.values()) {
            if (subject.equals(family.getSubject())) {
                result.add(family);
            }
        }
        result.sort(java.util.Comparator.comparingLong(RefreshFamily::getIssuedAt));
        return List.copyOf(result);
    }

    @Override
    public synchronized boolean logoutSession(String familyId,
                                              com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason reason) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            log.info("Session logout requested for unknown session: {}", familyId);
            return false;
        }
        if (family.isRevoked()) {
            // 已经注销/撤销：幂等视为"没有新的有效会话被关闭"。
            return false;
        }
        family.setRevoked(true);
        family.setLogoutReason(reason);
        family.setRevokeReason("session_logout:" + reason.name());
        flushTouchLocked();
        log.info("Session logged out: family={}, reason={}", familyId, reason);
        return true;
    }

    @Override
    public synchronized int logoutAllBySubject(String subject,
                                               com.github.highcumontoa.authaccesscontroljava.session.SessionLogoutReason reason) {
        int count = 0;
        long now = clock.epochSeconds();
        for (RefreshFamily family : families.values()) {
            if (subject.equals(family.getSubject()) && !family.isRevoked() && !family.isExpiredAt(now)) {
                family.setRevoked(true);
                family.setLogoutReason(reason);
                family.setRevokeReason("logout_all_sessions:" + reason.name());
                count++;
            }
        }
        if (count > 0) {
            flushTouchLocked();
        }
        log.info("Logged out all sessions for subject={}, count={}, reason={}", subject, count, reason);
        return count;
    }

    @Override
    public synchronized void touch(String familyId, long epochSeconds) {
        RefreshFamily family = families.get(familyId);
        if (family == null || family.isRevoked() || family.getLastUsedAt() >= epochSeconds) {
            return;
        }
        family.setLastUsedAt(epochSeconds);
        // 访问可能非常频繁：仅在距上次落盘超过节流窗口时写盘；注销/轮换等关键状态仍会立即落盘。
        if (epochSeconds - lastTouchFlushAt >= TOUCH_FLUSH_INTERVAL_SECONDS) {
            flushTouchLocked();
        }
    }

    /** 把累积的 lastUsedAt 变更立即落盘（关键状态变更路径会调用，保证注销前的时间戳不丢）。 */
    private void flushTouchLocked() {
        persistLocked();
        lastTouchFlushAt = clock.epochSeconds();
    }

    /** 刷新令牌原文格式：{@code <familyId>.<32字节随机hex>}；familyId 部分只用于定位族，无敏感性。 */
    private static String mintRawToken(String familyId) {
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        return familyId + "." + HmacSigner.hex(HmacSigner.sha256(random));
    }

    private static String hashToken(String rawToken) {
        return HmacSigner.hex(HmacSigner.sha256(HmacSigner.utf8(rawToken)));
    }

    private static String extractFamilyId(String rawToken) {
        if (rawToken == null) {
            return null;
        }
        int dot = rawToken.indexOf('.');
        if (dot <= 0 || dot >= rawToken.length() - 1) {
            return null;
        }
        return rawToken.substring(0, dot);
    }
}
