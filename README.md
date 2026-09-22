# 本地认证与访问控制服务（Java / Spring Boot）

一套**完全本地运行**的 Web 服务，演示并验证完整的认证与访问控制流程：

- 访问令牌（自描述 JWT，HS256）的**签发与校验**；
- 刷新令牌的**轮换（rotation）与撤销（revocation）**，并发/重复使用时**全进程最多成功一次**；
- 按**角色 / 作用域 / 资源归属**的接口访问控制；
- 主体维度**固定时间窗口限流**，高并发下精确不超量；
- 所有拒绝原因都有**稳定、可区分的错误码**，结论可解释、可复现；
- 不依赖任何外部服务；签名密钥只来自配置，**刷新令牌与密钥均不落盘为明文**。

---

## 1. 快速开始

要求 JDK 21+、Maven 3.9+（构建已验证可离线执行）。

```bash
# 构建并运行测试（无外部服务、无真实凭据）
mvn test

# 启动服务（默认端口 8080，可用 --server.port 覆盖）
mvn spring-boot:run
# 或
mvn package -DskipTests
java -jar target/auth-access-control-java-1.0-SNAPSHOT.jar
```

### 1.1 签名密钥（重要）

访问令牌的 HMAC 密钥**只能来自配置**，程序不会把它写入任何文件：

- 通过环境变量注入（推荐）：
  ```bash
  AUTH_HMAC_KEY="一段足够长的随机字符串" mvn spring-boot:run
  ```
- 未配置时，进程会在**内存中用 SecureRandom 生成一次性随机密钥**，并打印 WARN。
  此时功能正常，但**进程重启后此前签发的令牌必然验签失败**——这是可解释的预期行为，仅适合临时调试。

刷新令牌的撤销/轮换状态需要跨重启保持，因此会写入本地状态文件
（默认 `data/refresh-state.json`，已在 `.gitignore` 中忽略）。
文件里**只有刷新令牌的 SHA-256 哈希、代际号与撤销标记，没有任何明文令牌或密钥**。

---

## 2. 内置演示数据（全部为虚构凭据）

| 类型 | 标识 | 凭据 | 角色 / 作用域 |
| --- | --- | --- | --- |
| 用户 | `alice` | `alice-pass-123` | 角色 `USER`，用户ID `u-alice` |
| 用户 | `bob` | `bob-pass-123` | 角色 `USER`，用户ID `u-bob` |
| 用户 | `admin` | `admin-pass-123` | 角色 `USER`,`ADMIN`，用户ID `u-admin` |
| 客户端 | `client-web` | `web-secret` | 允许作用域 `read` `write` |
| 客户端 | `client-readonly` | `readonly-secret` | 仅允许作用域 `read` |
| 资源 | `res-1` | — | 属于 `u-alice` |
| 资源 | `res-2` | — | 属于 `u-bob` |

用户口令与客户端密钥在内存中只保留 SHA-256 哈希。

---

## 3. 令牌生命周期

### 3.1 访问令牌（Access Token）

- 形态为紧凑 JWT：`base64url(header).base64url(payload).base64url(HMAC-SHA256)`。
- 头部固定 `{"alg":"HS256","typ":"JWT"}`；`alg=none`、`RS256` 等一律拒绝。
- 载荷（payload）必需声明：`iss`、`sub`、`jti`、`iat`、`exp`、`clientId`、`fam`、`gen`；
  另有 `roles`、`scopes`、`aud`。
  - `fam`：刷新令牌**族（family）ID**；`gen`：该令牌所属的**代际号**。
- 默认有效期 10 分钟（`auth.token.accessTtlSeconds`）。
- 校验**完全在本地**完成（一次 HMAC 计算 + 声明检查 + 一次本地族状态查询），不访问外部服务。

校验按固定顺序执行，每种失败映射到不同错误码，结论可区分：

| 顺序 | 失败情形 | HTTP | error |
| --- | --- | --- | --- |
| 1 | 缺少 Authorization 头 / Bearer 后为空 | 401 | `missing_token` |
| 1 | 非 Bearer 方案、段数不对、base64 非法等 | 401 | `malformed_token` |
| 2 | `alg` 不是 HS256（含 `none`） | 401 | `unsupported_alg` |
| 3 | 签名不匹配（载荷/签名被篡改、密钥不同） | 401 | `bad_signature` |
| 4 | 缺少任一必需声明或声明为空 | 401 | `missing_claims` |
| 5 | `exp` 已到期 | 401 | `token_expired` |
| 6 | `iss` 与本服务配置不符 | 401 | `token_issuer_mismatch` |
| 7 | 令牌所属族已被撤销 | 401 | `token_family_revoked` |
| 7 | 令牌属于被轮换掉的旧代 / 族未知 | 401 | `token_family_stale` |
| 8 | 令牌主体与请求资源不符（见 §4） | 401 | `token_subject_mismatch` |

签名比较使用 `MessageDigest.isEqual`（常量时间），避免计时侧信道。

### 3.2 刷新令牌（Refresh Token）：族、轮换与撤销

- 每次 `password` 授权成功会创建一个**族（family）**，并签发原始刷新令牌：
  形态为 `<familyId>.<32字节随机数的SHA-256>`。
- **轮换**：使用刷新令牌时，服务在同一把锁内原子地完成
  「校验哈希 → 生成新随机令牌 → 覆盖当前哈希 → gen+1 → 落盘」。
  因此：
  - 同一刷新令牌**无论串行重放还是并发重复使用，全进程最多有一次成功**，其余得到 `invalid_grant_replayed`；
  - 旧刷新令牌立即失效；轮换产生的是**新的刷新令牌**，需要保存使用。
- 每次轮换都会让**旧访问令牌失效**：访问令牌携带 `gen`，与族当前代不一致即被拒（`token_family_stale`）。
- **撤销**：撤销作用于整个族（RFC 7009 风格）。撤销后该族的**所有**刷新令牌与历史访问令牌都被拒
  （`invalid_grant_revoked` / `token_family_revoked`）。
- **进程重启一致性**：族状态（含 `revoked`、当前哈希、代际、角色/作用域）以 JSON 持久化，
  启动时加载。已撤销族不会被清理，保证重启后仍给出 `revoked` 而不是退化为「未知」。
  写盘采用「临时文件 + 原子 move」。

刷新端点的拒绝原因彼此可区分：

| 情形 | HTTP | error |
| --- | --- | --- |
| 刷新令牌未知 / 形态无法解析 | 400 | `invalid_grant` |
| 令牌不是签发给当前客户端的 | 400 | `invalid_grant_client_mismatch` |
| 族已过期 | 400 | `invalid_grant_expired` |
| 族已被撤销 | 400 | `invalid_grant_revoked` |
| 旧令牌重放 / 并发重复使用 | 400 | `invalid_grant_replayed` |
| 客户端不存在 / 密钥错误 | 401 | `invalid_client` |
| 请求了客户端不具备的作用域 | 400 | `invalid_scope` |
| 不支持的 grant_type | 400 | `unsupported_grant_type` |
| 缺少必要参数 / body 非法 | 400 | `invalid_request` |

> 客户端不符的请求**不会消费**刷新令牌：真正的客户端之后仍可成功轮换一次。

---

## 4. 访问控制模型

认证（`AuthFilter`，只拦截 `/api/**`）通过后，鉴权由 `AuthorizationInterceptor` 依次执行：

1. **角色**：方法/类上的 `@RequireRole({"ADMIN"})`，主体 `roles` 命中其一即可，否则 403 `forbidden_role`。
2. **作用域**：`@RequireScope({"read"})`，主体 `scopes` 命中其一即可，否则 403 `forbidden_scope`。
3. **主体 / 资源归属**：`@SubjectScoped`
   - `pathVariable="userId"`：路径中的用户 ID 必须等于令牌 `sub`（ADMIN 豁免），否则 401 `token_subject_mismatch`；
   - `pathVariable="resourceId"`：资源必须存在且 `owner == sub`，否则 403 `forbidden_owner`。
4. **限流**（见 §5）。

| 端点 | 要求 |
| --- | --- |
| `GET /api/ping` | 仅认证 + 限流 |
| `GET /api/profile/{userId}` | 作用域 `read` + 主体一致 |
| `GET /api/admin/users` | 角色 `ADMIN` + 作用域 `read` |
| `GET /api/resources/{resourceId}` | 作用域 `read` + 资源归属 |

---

## 5. 限流模型

- 维度：**认证主体**（令牌 `sub`），不同主体互不影响。
- 算法：**固定时间窗口**。默认每主体 60 秒最多 10 个请求
  （`auth.ratelimit.maxRequests` / `auth.ratelimit.windowSeconds`）。
- 「窗口翻转判定 + 计数自增」在同一把锁内原子完成，因此**高并发下绝不会放行超过上限的请求**
  （`RateLimitServiceTest` 用 500 线程 / 上限 100 验证「恰好 100 个通过」）。
- 超量返回 429，错误码 `rate_limited`，响应描述中含上限与窗口长度。

---

## 6. 本地验证手册（curl）

以下示例假设服务运行在 `http://localhost:8080`。

```bash
# 1) 密码模式登录（alice）
RESP=$(curl -s -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"client-web","client_secret":"web-secret",
       "username":"alice","password":"alice-pass-123"}')
AT=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
RT=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["refresh_token"])')

# 2) 访问自己的资料：200
curl -s http://localhost:8080/api/profile/u-alice -H "Authorization: Bearer $AT"

# 3) 主体不符（alice 访问 bob）：401 token_subject_mismatch
curl -s http://localhost:8080/api/profile/u-bob -H "Authorization: Bearer $AT"

# 4) 篡改签名最后一位：401 bad_signature
BAD="${AT%?}X"
curl -s http://localhost:8080/api/ping -H "Authorization: Bearer $BAD"

# 5) 轮换刷新令牌：200，返回新的 access_token / refresh_token
curl -s -X POST http://localhost:8080/oauth/token -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"refresh_token\",\"client_id\":\"client-web\",
       \"client_secret\":\"web-secret\",\"refresh_token\":\"$RT\"}"

# 6) 再次使用旧刷新令牌：400 invalid_grant_replayed
# 7) 旧访问令牌：401 token_family_stale

# 8) 撤销（族）
curl -s -X POST http://localhost:8080/oauth/revoke -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"client-web\",\"client_secret\":\"web-secret\",\"token\":\"$RT\"}"
# 撤销后：访问令牌 401 token_family_revoked；刷新令牌 400 invalid_grant_revoked

# 9) 角色不足：alice 访问管理接口：403 forbidden_role
# 10) 作用域/归属：见 §4
# 11) 连发 >10 次 /api/ping：第 11 次起 429 rate_limited
```

### 6.1 重启一致性

```bash
# 撤销一个族后停止服务，再重新启动（使用同一个 AUTH_HMAC_KEY 与默认状态文件）
AUTH_HMAC_KEY="stable-key" mvn spring-boot:run
# ... 登录 -> /oauth/revoke ...
# Ctrl-C 停止后再次 AUTH_HMAC_KEY="stable-key" mvn spring-boot:run
# 此前被撤销族的令牌依旧返回 token_family_revoked / invalid_grant_revoked
```

---

## 7. 测试

```bash
mvn test
```

共 42 个测试，全部可在无外部服务、无真实凭据条件下运行：

| 测试类 | 覆盖内容 |
| --- | --- |
| `MaskersTest` | 令牌/密钥脱敏不泄露原文、指纹稳定不可逆 |
| `AccessTokenServiceTest` | 过期、载荷/签名篡改、`none`/异算法、缺声明、签发者不符、异密钥——错误码逐一区分 |
| `RefreshTokenStoreTest` | 轮换、32 线程并发恰一次成功、未知/客户端不符/过期/撤销可区分、状态文件只含哈希、重启重载 |
| `RateLimitServiceTest` | 固定窗口上限、主体隔离、窗口翻转、500 线程恰好不超量 |
| `AuthFlowIntegrationTest` | 全栈：登录、缺/畸形令牌、篡改、主体不符、角色、作用域、归属、刷新轮换与重放、撤销 |
| `RateLimitIntegrationTest` | HTTP 端到端恰好 10 个通过、第 11 个 429 |
| `ExpiryIntegrationTest` | 可控时钟推进后访问令牌 `token_expired`（无需真实等待） |
| `RefreshExpiryIntegrationTest` | 刷新族过期 `invalid_grant_expired` |
| `PersistenceRestartTest` | 真实创建/关闭两个 Spring 上下文读写同一文件，验证重启后撤销结论一致 |

令牌过期类测试通过可替换的 `Clock` Bean 推进时间，结论确定、无需睡眠。

---

## 8. 日志脱敏

所有关键判定都会记录依据，但敏感字段一律经 `Maskers` 处理：

- 令牌：`eyJhbGci...(len=452,fp=631d3c7a41e7)`（仅保留 8 字符前缀 + 长度 + SHA-256 短指纹）；
- 密钥/口令：固定 `******`；
- 刷新令牌：族 ID 可记录（非秘密），令牌本体仅记录脱敏形态。

---

## 9. 配置项一览（`application.properties`）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTH_HMAC_KEY` / `auth.security.hmacKey` | 内置本地开发占位值 | HMAC 签名密钥；不落盘，建议用环境变量覆盖 |
| `auth.security.issuer` | `local-auth-service` | 令牌签发者，校验 `iss` |
| `auth.token.accessTtlSeconds` | `600` | 访问令牌有效期 |
| `auth.token.refreshTtlSeconds` | `1209600` | 刷新令牌族有效期（14 天） |
| `auth.token.stateFile` | `data/refresh-state.json` | 族状态文件（仅哈希/标记） |
| `auth.ratelimit.maxRequests` | `10` | 每主体每窗口上限 |
| `auth.ratelimit.windowSeconds` | `60` | 限流窗口长度 |
