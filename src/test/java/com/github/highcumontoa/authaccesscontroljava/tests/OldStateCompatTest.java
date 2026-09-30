package com.github.highcumontoa.authaccesscontroljava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.highcumontoa.authaccesscontroljava.config.AuthProperties;
import com.github.highcumontoa.authaccesscontroljava.support.Clock;
import com.github.highcumontoa.authaccesscontroljava.token.FileRefreshTokenStore;
import com.github.highcumontoa.authaccesscontroljava.token.RefreshTokenStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class OldStateCompatTest {

    @Test
    void legacyStateFileWithoutNewFieldsLoadsWithDefaults() throws Exception {
        Path f = Files.createTempFile("legacy-state", ".json");
        // 模拟上一版本写出的文件：没有 lastUsedAt / logoutReason 字段。
        String legacy = """
            [ {
              "familyId" : "fam-legacy",
              "subject" : "u-alice",
              "clientId" : "client-web",
              "generation" : 3,
              "currentTokenHash" : "abc123",
              "issuedAt" : 1700000000,
              "expiresAt" : 1900000000,
              "revoked" : false,
              "roles" : [ "USER" ],
              "scopes" : [ "read" ]
            } ]
            """;
        Files.writeString(f, legacy);
        AuthProperties props = new AuthProperties();
        props.getToken().setStateFile(f.toString());
        FileRefreshTokenStore store = new FileRefreshTokenStore(props, new Clock());

        assertThat(store.familyStatus("fam-legacy", 3))
                .isEqualTo(RefreshTokenStore.FamilyStatus.ACTIVE_CURRENT);
        assertThat(store.listBySubject("u-alice")).hasSize(1);
        // 旧文件没有 lastUsedAt：读取为 0，不影响校验；会话概览层会回退展示建立时间。
        assertThat(store.listBySubject("u-alice").get(0).getLastUsedAt()).isEqualTo(0L);
        assertThat(store.listBySubject("u-alice").get(0).getIssuedAt()).isEqualTo(1700000000L);
        Files.deleteIfExists(f);
    }
}
