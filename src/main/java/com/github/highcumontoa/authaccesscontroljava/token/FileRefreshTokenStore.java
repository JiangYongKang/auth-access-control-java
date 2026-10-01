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
    /** lastUsedAt 落盘节流间隔：距上次持久化不足该秒数时只更新内存，避免每个请求都写盘。 */
    private static final long TOUCH_PERSIST_INTERVAL_SECONDS = 60L;

    private final Path stateFile;
    private final Clock clock;
    private final Map<String, RefreshFamily> families = new HashMap<>();

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
        family.setRoles(java.util.List.copyOf(roles));
        family.setScopes(java.util.List.copyOf(scopes));
        family.setLastUsedAt(now);
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
        family.setLastUsedAt(now);
        persistLocked();
        log.info("Refresh rotated successfully: family={}, newGen={}", familyId, family.getGeneration());
        return new RotationResult(RotationOutcome.SUCCESS, family,
                new StoredToken(nextRaw, familyId, family.getGeneration()));
    }

    @Override
    public synchronized void revoke(String familyId, String reason, RevocationCause cause) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            log.info("Revoke requested for unknown family: {}", familyId);
            return;
        }
        if (!family.isRevoked()) {
            family.setRevoked(true);
            family.setRevokeReason(reason == null ? "explicit_revoke" : reason);
            family.setRevocationCause(cause == null ? RevocationCause.TOKEN_REVOCATION : cause);
            persistLocked();
            log.info("Refresh family revoked: family={}, cause={}, reason={}",
                    familyId, family.getRevocationCause(), family.getRevokeReason());
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
            return FamilyStatus.REVOKED;
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
    public synchronized FamilyRevocation familyRevocation(String familyId, long generation) {
        RefreshFamily family = families.get(familyId);
        if (family == null) {
            return FamilyRevocation.of(FamilyStatus.UNKNOWN);
        }
        if (family.isRevoked()) {
            return new FamilyRevocation(FamilyStatus.REVOKED, family.effectiveRevocationCause());
        }
        if (family.isExpiredAt(clock.epochSeconds())) {
            // 族已过期等同于状态不可再确认，按"非当前"处理。
            return FamilyRevocation.of(FamilyStatus.UNKNOWN);
        }
        return FamilyRevocation.of(family.getGeneration() == generation
                ? FamilyStatus.ACTIVE_CURRENT
                : FamilyStatus.ACTIVE_STALE);
    }

    @Override
    public synchronized SessionRevokeOutcome revokeSessionAtomically(String familyId, String subject,
                                                                     String reason, long nowEpochSeconds) {
        RefreshFamily family = families.get(familyId);
        // 族不存在或不属于发起主体：统一报 NOT_FOUND，不向调用方泄露其它主体会话的存在。
        if (family == null || !subject.equals(family.getSubject())) {
            log.info("Session revoke: session not found: family={}, subject={}", familyId, subject);
            return SessionRevokeOutcome.NOT_FOUND;
        }
        if (family.isRevoked()) {
            // 并发/重复注销的落败者都在这里汇合：第一次之后再无 REVOKED。
            log.info("Session revoke: session already revoked: family={}", familyId);
            return SessionRevokeOutcome.ALREADY_REVOKED;
        }
        if (family.isExpiredAt(nowEpochSeconds)) {
            log.info("Session revoke: session expired: family={}, expiredAt={}, now={}",
                    familyId, family.getExpiresAt(), nowEpochSeconds);
            return SessionRevokeOutcome.EXPIRED;
        }
        // 检查通过：在同一把锁内立即撤销并落盘，随后到达的任何重复请求只能得到 ALREADY_REVOKED。
        family.setRevoked(true);
        family.setRevokeReason(reason == null ? "admin_session_logout" : reason);
        family.setRevocationCause(RevocationCause.SESSION_LOGOUT);
        persistLocked();
        log.info("Session revoked atomically: family={}, subject={}", familyId, subject);
        return SessionRevokeOutcome.REVOKED;
    }

    @Override
    public synchronized void touch(String familyId, long epochSeconds) {
        RefreshFamily family = families.get(familyId);
        if (family == null || family.isRevoked()) {
            return;
        }
        if (epochSeconds <= family.getLastUsedAt()) {
            return;
        }
        boolean shouldPersist =
                epochSeconds - family.getLastUsedAt() >= TOUCH_PERSIST_INTERVAL_SECONDS;
        family.setLastUsedAt(epochSeconds);
        if (shouldPersist) {
            persistLocked();
        }
    }

    @Override
    public synchronized List<RefreshFamily> listActiveSessions(String subject) {
        long now = clock.epochSeconds();
        return families.values().stream()
                .filter(f -> subject.equals(f.getSubject()))
                .filter(f -> !f.isRevoked() && !f.isExpiredAt(now))
                .sorted(java.util.Comparator.comparingLong(RefreshFamily::getIssuedAt))
                .toList();
    }

    @Override
    public synchronized int revokeSessionsBySubject(String subject, String reason) {
        long now = clock.epochSeconds();
        int count = 0;
        boolean changed = false;
        for (RefreshFamily family : families.values()) {
            if (!subject.equals(family.getSubject())) {
                continue;
            }
            if (family.isRevoked() || family.isExpiredAt(now)) {
                continue;
            }
            family.setRevoked(true);
            family.setRevokeReason(reason == null ? "session_logout" : reason);
            family.setRevocationCause(RevocationCause.SESSION_LOGOUT);
            changed = true;
            count++;
        }
        if (changed) {
            persistLocked();
            log.info("All sessions revoked for subject={}, count={}, reason={}", subject, count, reason);
        }
        return count;
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
