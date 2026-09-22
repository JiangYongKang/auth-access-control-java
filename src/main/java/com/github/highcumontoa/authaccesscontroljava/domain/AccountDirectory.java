package com.github.highcumontoa.authaccesscontroljava.domain;

import com.github.highcumontoa.authaccesscontroljava.token.HmacSigner;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * 内存账户目录：用本地固定数据模拟"用户库 / 客户端注册表 / 资源库"，不连任何外部服务。
 *
 * <p>口令与客户端密钥在代码中只保留 SHA-256 哈希常量，校验时对输入做同样哈希后比较。
 * （演示数据见 README，均为虚构凭据。）
 */
@Component
public class AccountDirectory {

    private final Map<String, UserAccount> usersByUsername = new LinkedHashMap<>();
    private final Map<String, UserAccount> usersById = new LinkedHashMap<>();
    private final Map<String, ClientApp> clients = new LinkedHashMap<>();
    private final Map<String, OwnedResource> resources = new LinkedHashMap<>();

    public AccountDirectory() {
        seed();
    }

    private void seed() {
        addUser(new UserAccount("u-alice", "alice", sha256("alice-pass-123"), List.of("USER")));
        addUser(new UserAccount("u-bob", "bob", sha256("bob-pass-123"), List.of("USER")));
        addUser(new UserAccount("u-admin", "admin", sha256("admin-pass-123"), List.of("USER", "ADMIN")));

        clients.put("client-web",
                new ClientApp("client-web", sha256("web-secret"), List.of("read", "write")));
        clients.put("client-readonly",
                new ClientApp("client-readonly", sha256("readonly-secret"), List.of("read")));

        resources.put("res-1", new OwnedResource("res-1", "u-alice", "Alice's notebook"));
        resources.put("res-2", new OwnedResource("res-2", "u-bob", "Bob's checklist"));
    }

    private void addUser(UserAccount user) {
        usersByUsername.put(user.username(), user);
        usersById.put(user.id(), user);
    }

    private static String sha256(String raw) {
        return HmacSigner.hex(HmacSigner.sha256(HmacSigner.utf8(raw)));
    }

    public Optional<UserAccount> findUserByUsername(String username) {
        return Optional.ofNullable(usersByUsername.get(username));
    }

    public Optional<UserAccount> findUserById(String userId) {
        return Optional.ofNullable(usersById.get(userId));
    }

    public Optional<ClientApp> findClient(String clientId) {
        return Optional.ofNullable(clients.get(clientId));
    }

    public boolean checkUserPassword(UserAccount user, String rawPassword) {
        return rawPassword != null && sha256(rawPassword).equals(user.passwordHash());
    }

    public boolean checkClientSecret(ClientApp client, String rawSecret) {
        return rawSecret != null && sha256(rawSecret).equals(client.clientSecret());
    }

    public Optional<OwnedResource> findResource(String resourceId) {
        return Optional.ofNullable(resources.get(resourceId));
    }
}
