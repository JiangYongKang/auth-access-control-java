package com.github.highcumontoa.authaccesscontroljava.token;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;

/**
 * 基于本地 JSON 文件的令牌状态存储。
 *
 * <ul>
 *   <li>每个刷新令牌属于一个“家族(family)”，轮换在家族内进行；重复使用已轮换令牌会撤销整个家族。</li>
 *   <li>所有变更在同一把全局锁内完成并原子落盘（临时文件 + move），因此并发刷新最多成功一次。</li>
 *   <li>文件写入额外使用 FileLock 串行化，保证跨进程/重启后撤销与重放结论一致。</li>
 *   <li>轮换或撤销时，关联的访问令牌 jti 进入 deniedAccessJtis 清单并立即失效。</li>
 *   <li>刷新令牌仅保存 SHA-256 指纹(refreshHash)，不保存原始令牌。</li>
 * </ul>
 */
public class FileTokenStateStore implements TokenStateStore {

    private static final Logger log = LoggerFactory.getLogger(FileTokenStateStore.class);

    private final Path file;
    private final long graceWindowMs;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    /** 全局状态锁：保证 rotate 的“检查-状态翻转-登记新令牌”原子性 */
    private final Object monitor = new Object();

    private State state = new State();

    public FileTokenStateStore(AuthProperties properties, Clock clock, ObjectMapper objectMapper) {
        this.file = Path.of(properties.getRefresh().getStorePath());
        this.graceWindowMs = properties.getRefresh().getGraceWindow().toMillis();
        this.clock = clock;
        this.objectMapper = objectMapper.copy()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        load();
    }

    private void load() {
        synchronized (monitor) {
            if (!Files.exists(file)) {
                return;
            }
            try {
                byte[] bytes = Files.readAllBytes(file);
                if (bytes.length == 0) {
                    return;
                }
                this.state = objectMapper.readValue(bytes, State.class);
                if (this.state.families == null) {
                    this.state.families = new ArrayList<>();
                }
                if (this.state.deniedAccessJtis == null) {
                    this.state.deniedAccessJtis = new ArrayList<>();
                }
                log.info("加载令牌状态: families={}, deniedAccessJtis={}",
                        state.families.size(), state.deniedAccessJtis.size());
            } catch (IOException ex) {
                throw new UncheckedIOException("无法读取令牌状态文件: " + file, ex);
            }
        }
    }

    private void persistLocked() {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            byte[] bytes = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(state);
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                // 跨进程串行化写
                try (FileLock ignored = channel.lock()) {
                    channel.write(java.nio.ByteBuffer.wrap(bytes));
                }
            }
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ex) {
            throw new UncheckedIOException("无法持久化令牌状态文件: " + file, ex);
        }
    }

    @Override
    public TokenState createFamily(String subject, String clientId, String refreshHash, String refreshJti,
                                   long expiresAtEpochMs, String currentAccessJti,
                                   List<String> scopes) {
        synchronized (monitor) {
            long now = clock.instant().toEpochMilli();
            Family family = new Family();
            family.id = java.util.UUID.randomUUID().toString().replace("-", "");
            family.subject = subject;
            family.clientId = clientId;
            family.revoked = false;
            family.createdAt = now;
            family.currentAccessJti = currentAccessJti;
            family.scopes = scopes == null ? List.of() : List.copyOf(scopes);

            TokenEntry entry = new TokenEntry();
            entry.hash = refreshHash;
            entry.jti = refreshJti;
            entry.status = TokenStatus.ACTIVE.name();
            entry.issuedAt = now;
            entry.expiresAt = expiresAtEpochMs;
            entry.rotatedAt = null;
            family.tokens = new ArrayList<>(List.of(entry));

            state.families.add(family);
            persistLocked();
            log.info("创建刷新令牌家族: familyId={}, sub={}, cid={}", family.id, subject, clientId);
            return new TokenState(family.id, family.subject, family.clientId);
        }
    }

    @Override
    public RotationOutcome rotate(String refreshHash, String clientId, String newRefreshHash,
                                  String newRefreshJti, long newExpiresAtEpochMs,
                                  String newAccessJti) {
        synchronized (monitor) {
            long now = clock.instant().toEpochMilli();
            Located located = locate(refreshHash);
            if (located == null) {
                throw new RefreshRejectedException(RefreshRejectReason.NOT_FOUND);
            }
            Family family = located.family;
            TokenEntry old = located.entry;

            if (family.revoked || TokenStatus.REVOKED.name().equals(old.status)) {
                throw new RefreshRejectedException(RefreshRejectReason.REVOKED);
            }
            if (!family.clientId.equals(clientId)) {
                throw new RefreshRejectedException(RefreshRejectReason.CLIENT_MISMATCH);
            }

            if (TokenStatus.ROTATED.name().equals(old.status)) {
                // 旧令牌已被成功使用过一次：并发宽限窗口内视为并发复用，否则视为重放攻击。
                boolean withinGrace = old.rotatedAt != null && now - old.rotatedAt <= graceWindowMs;
                if (withinGrace) {
                    log.warn("刷新令牌并发复用被拒绝: familyId={}", family.id);
                    throw new RefreshRejectedException(RefreshRejectReason.CONCURRENT_REUSE);
                }
                // 重放：撤销整个家族，且不再签发任何新令牌
                revokeFamilyInternal(family, now, "检测到已轮换刷新令牌重放");
                persistLocked();
                throw new RefreshRejectedException(RefreshRejectReason.REPLAYED);
            }

            // ACTIVE：过期判断
            if (old.expiresAt <= now) {
                throw new RefreshRejectedException(RefreshRejectReason.EXPIRED);
            }

            // 原子翻转：当前线程已持有 monitor，只有一个线程能走到这里
            old.status = TokenStatus.ROTATED.name();
            old.rotatedAt = now;

            TokenEntry next = new TokenEntry();
            next.hash = newRefreshHash;
            next.jti = newRefreshJti;
            next.status = TokenStatus.ACTIVE.name();
            next.issuedAt = now;
            next.expiresAt = newExpiresAtEpochMs;
            next.rotatedAt = null;
            family.tokens.add(next);

            // 旧访问令牌立即进入拒绝清单，并登记新访问令牌 jti
            String oldAccessJti = family.currentAccessJti;
            if (oldAccessJti != null && !state.deniedAccessJtis.contains(oldAccessJti)) {
                state.deniedAccessJtis.add(oldAccessJti);
            }
            family.currentAccessJti = newAccessJti;
            persistLocked();
            log.info("刷新令牌轮换成功: familyId={}, sub={}", family.id, family.subject);
            return new RotationOutcome(family.id, family.subject, family.clientId,
                    TokenStatus.ROTATED.name(), false, family.scopes);
        }
    }

    @Override
    public boolean revokeFamily(String refreshHash, String clientId) {
        synchronized (monitor) {
            long now = clock.instant().toEpochMilli();
            Located located = locate(refreshHash);
            if (located == null) {
                throw new RefreshRejectedException(RefreshRejectReason.NOT_FOUND);
            }
            if (!located.family.clientId.equals(clientId)) {
                throw new RefreshRejectedException(RefreshRejectReason.CLIENT_MISMATCH);
            }
            if (located.family.revoked) {
                return false;
            }
            revokeFamilyInternal(located.family, now, "客户端主动撤销/登出");
            persistLocked();
            return true;
        }
    }

    private void revokeFamilyInternal(Family family, long now, String reason) {
        family.revoked = true;
        family.revokedAt = now;
        for (TokenEntry entry : family.tokens) {
            entry.status = TokenStatus.REVOKED.name();
        }
        if (family.currentAccessJti != null
                && !state.deniedAccessJtis.contains(family.currentAccessJti)) {
            state.deniedAccessJtis.add(family.currentAccessJti);
        }
        log.warn("刷新令牌家族被撤销: familyId={}, sub={}, reason={}", family.id, family.subject, reason);
    }

    @Override
    public boolean isFamilyRevoked(String familyId) {
        synchronized (monitor) {
            for (Family family : state.families) {
                if (family.id.equals(familyId)) {
                    return family.revoked;
                }
            }
            return false;
        }
    }

    @Override
    public String tokenStatus(String refreshHash) {
        synchronized (monitor) {
            Located located = locate(refreshHash);
            return located == null ? "UNKNOWN" : located.entry.status;
        }
    }

    @Override
    public boolean isAccessDenied(String jti) {
        synchronized (monitor) {
            return state.deniedAccessJtis.contains(jti);
        }
    }

    private Located locate(String refreshHash) {
        for (Family family : state.families) {
            if (family.tokens == null) {
                continue;
            }
            for (TokenEntry entry : family.tokens) {
                if (entry.hash.equals(refreshHash)) {
                    return new Located(family, entry);
                }
            }
        }
        return null;
    }

    private record Located(Family family, TokenEntry entry) {
    }

    private enum TokenStatus {
        ACTIVE, ROTATED, REVOKED
    }

    /** 持久化根结构 */
    public static class State {
        public List<Family> families = new ArrayList<>();
        public List<String> deniedAccessJtis = new ArrayList<>();
    }

    public static class Family {
        public String id;
        public String subject;
        public String clientId;
        public boolean revoked;
        public Long createdAt;
        public Long revokedAt;
        /** 当前配套访问令牌的 jti；轮换/撤销后进入 deniedAccessJtis */
        public String currentAccessJti;
        /** 授权作用域，刷新后新访问令牌继续携带 */
        public List<String> scopes = new ArrayList<>();
        public List<TokenEntry> tokens = new ArrayList<>();
    }

    public static class TokenEntry {
        public String hash;
        public String jti;
        public String status;
        public long issuedAt;
        public long expiresAt;
        public Long rotatedAt;
    }
}
