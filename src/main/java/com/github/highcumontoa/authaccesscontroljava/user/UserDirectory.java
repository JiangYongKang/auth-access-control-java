package com.github.highcumontoa.authaccesscontroljava.user;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.security.SecretHasher;

/**
 * 本地用户与客户端目录（内存状态，来源为本地配置）。
 * 密码与客户端密钥仅保存 PBKDF2 哈希，认证使用恒定时间比较。
 */
@Component
public class UserDirectory {

    private static final Logger log = LoggerFactory.getLogger(UserDirectory.class);

    private final AuthProperties properties;

    public UserDirectory(AuthProperties properties) {
        this.properties = properties;
    }

    public Optional<AuthenticatedUser> authenticateUser(String username, char[] password) {
        if (username == null || password == null) {
            return Optional.empty();
        }
        Optional<AuthProperties.UserConfig> config = properties.getUsers().stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst();
        if (config.isEmpty()) {
            log.warn("用户认证失败: 用户不存在 username={}", username);
            return Optional.empty();
        }
        if (!SecretHasher.pbkdf2Matches(password, config.get().getPasswordHash())) {
            log.warn("用户认证失败: 口令不匹配 username={}", username);
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedUser(config.get().getUsername(),
                List.copyOf(config.get().getRoles())));
    }

    public Optional<AuthenticatedClient> authenticateClient(String clientId, char[] secret) {
        if (clientId == null || secret == null) {
            return Optional.empty();
        }
        Optional<AuthProperties.ClientConfig> config = properties.getClients().stream()
                .filter(c -> c.getClientId().equals(clientId))
                .findFirst();
        if (config.isEmpty()) {
            log.warn("客户端认证失败: client 不存在 clientId={}", clientId);
            return Optional.empty();
        }
        if (!SecretHasher.pbkdf2Matches(secret, config.get().getSecretHash())) {
            log.warn("客户端认证失败: 密钥不匹配 clientId={}", clientId);
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedClient(config.get().getClientId(),
                List.copyOf(config.get().getScopes())));
    }

    public Optional<AuthenticatedClient> findClient(String clientId) {
        return properties.getClients().stream()
                .filter(c -> c.getClientId().equals(clientId))
                .map(c -> new AuthenticatedClient(c.getClientId(), List.copyOf(c.getScopes())))
                .findFirst();
    }

    public Optional<AuthenticatedUser> findUser(String username) {
        return properties.getUsers().stream()
                .filter(u -> u.getUsername().equals(username))
                .map(u -> new AuthenticatedUser(u.getUsername(), List.copyOf(u.getRoles())))
                .findFirst();
    }

    public record AuthenticatedUser(String username, List<String> roles) {
    }

    public record AuthenticatedClient(String clientId, List<String> scopes) {
    }
}
