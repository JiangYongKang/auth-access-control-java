# 本地认证与访问控制服务（Java / Spring Boot）

一套**完全本地运行**的 Web 服务，演示并验证完整的认证与访问控制流程：

- 访问令牌（自描述 JWT，HS256）的**签发与校验**；
- **签名密钥平滑轮换**：可同时配置多把密钥并指定当前签发密钥；旧密钥保留期间旧令牌继续可验，
  旧密钥一摘除其令牌**立即失效**；「不认识/已摘除的密钥」与「签名本身对不上」是**两个不同错误码**；
- **用户会话可见、可定向踢出**：同一用户不同客户端是互不影响的会话，可列表、可单个注销、可一次性清空，
  注销后该会话已签发的访问令牌立即失效；状态跨进程重启保持一致；
- 供内部网关使用的**只读令牌自检入口**（RFC 7662 风格），区分有效与各类无效原因，查询不改变状态；
- 刷新令牌的**轮换（rotation）与撤销（revocation）**，并发/重复使用时**全进程最多成功一次**；
- 按**角色 / 作用域 / 资源归属**的接口访问控制；
- 主体维度**固定时间窗口限流**，高并发下精确不超量；
- 所有拒绝原因都有**稳定、可区分的错误码**，结论可解释、可复现；
- 不依赖任何外部服务；签名密钥只来自配置、只在内存中（**绝不落盘明文**），刷新/会话状态文件只含哈希与标记。

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

### 1.1 签名密钥与平滑轮换（重要）

访问令牌的 HMAC 密钥**只能来自配置**，在进程内存中持有，程序**绝不会把密钥写入任何文件**。

**方式一：多密钥平滑轮换（推荐）**

```properties
# 可配置任意多把；keyId 自定义（建议带日期/版本），值是密钥原文
auth.security.signing-keys.k2026-03=${AUTH_HMAC_KEY_K2026_03:旧密钥随机串}
auth.security.signing-keys.k2026-09=${AUTH_HMAC_KEY_K2026_09:新密钥随机串}
# 指定其中一把为"当前签发密钥"：新签发的令牌一律带 kid=该 ID
auth.security.active-key-id=k2026-09
```

轮换步骤（在线用户不掉线）：

1. **加入新密钥**：把新密钥加进 `signing-keys`，把 `active-key-id` 指到新密钥，
   **先保留旧密钥**，滚动重启网关后的本服务；
2. 此后新登录/刷新得到的令牌由新密钥（`k2026-09`）签发；
   线上尚未到期、由旧密钥（`k2026-03`）签发的令牌，因为旧密钥仍在配置里，**继续通过校验**；
3. 等一个访问令牌有效期（默认 10 分钟）过后，再把**旧密钥从配置里摘掉**并重启；
   由它签发的令牌从这一刻起**立即失效**，错误码 `unknown_signing_key`；
4. 校验时「kid 对应的密钥已摘除/从未配置」→ `unknown_signing_key`，
   与「密钥仍在、但签名对不上（被篡改）」→ `bad_signature`，是**两个明确分开的结论**。

> JWT 头部新增 `kid`。切换密钥不需要也不会改动会话状态文件；密钥与状态文件相互独立。
> 若 `active-key-id` 指向了一个不在 `signing-keys` 里的 ID，进程会在启动时直接失败（fail-fast）。

**方式二：单密钥兼容（与上一版本完全一致）**

- 通过环境变量注入（向后兼容）：
  ```bash
  AUTH_HMAC_KEY="一段足够长的随机字符串" mvn spring-boot:run
  ```
  这等价于只配置了一把 ID 为 `default` 的密钥，且它就是当前密钥；无 `kid` 的旧令牌按 `default` 兼容验签。
- 未配置任何密钥时，进程会在**内存中用 SecureRandom 生成一次性随机密钥**，并打印 WARN。
  此时功能正常，但**进程重启后此前签发的令牌必然验签失败**——这是可解释的预期行为，仅适合临时调试。

刷新令牌的撤销/轮换与**会话注销状态**需要跨重启保持，因此会写入本地状态文件
（默认 `data/refresh-state.json`，已在 `.gitignore` 中忽略）。
文件里**只有刷新令牌的 SHA-256 哈希、代际号、注销/撤销标记和会话时间戳，没有任何明文令牌或密钥**。

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
- 头部为 `{"alg":"HS256","typ":"JWT","kid":"<当前密钥ID>"}`；`alg=none`、`RS256` 等一律拒绝。
  `kid` 标识签发所用密钥（轮换用，非秘密）；无 `kid` 的旧令牌按兼容密钥 `default` 验签。
- 载荷（payload）必需声明：`iss`、`sub`、`jti`、`iat`、`exp`、`clientId`、`fam`、`gen`；
  另有 `roles`、`scopes`、`aud`。
  - `fam`：刷新令牌**族（family）ID**，同时也是**会话 ID**；`gen`：该令牌所属的**代际号**。
- 默认有效期 10 分钟（`auth.token.accessTtlSeconds`）。
- 校验**完全在本地**完成（一次 HMAC 计算 + 声明检查 + 一次本地族/会话状态查询），不访问外部服务。

校验按固定顺序执行，每种失败映射到不同错误码，结论可区分：

| 顺序 | 失败情形 | HTTP | error |
| --- | --- | --- | --- |
| 1 | 缺少 Authorization 头 / Bearer 后为空 | 401 | `missing_token` |
| 1 | 非 Bearer 方案、段数不对、base64 非法等 | 401 | `malformed_token` |
| 2 | `alg` 不是 HS256（含 `none`） | 401 | `unsupported_alg` |
| 3 | `kid` 对应的密钥已摘除/从未配置 | 401 | `unknown_signing_key` |
| 3 | 密钥仍在但签名不匹配（载荷/签名被篡改） | 401 | `bad_signature` |
| 4 | 缺少任一必需声明或声明为空 | 401 | `missing_claims` |
| 5 | `exp` 已到期 | 401 | `token_expired` |
| 6 | `iss` 与本服务配置不符 | 401 | `token_issuer_mismatch` |
| 7 | 令牌所属会话被注销（单个/批量） | 401 | `token_session_logged_out` |
| 7 | 令牌所属族被撤销（RFC 7009 / 异常重放联动） | 401 | `token_family_revoked` |
| 7 | 令牌属于被轮换掉的旧代 / 族未知 | 401 | `token_family_stale` |
| 8 | 令牌主体与请求资源不符（见 §4） | 401 | `token_subject_mismatch` |

`unknown_signing_key` 与 `bad_signature` 的区分是刻意的：前者表示「这把密钥我已经不认识了」
（运维摘除密钥的预期效果），后者表示「密钥认识，但这段签名算出来对不上」（典型篡改信号）。
签名比较使用 `MessageDigest.isEqual`（常量时间）；找不到 kid 时也执行一次等长 HMAC，避免时序侧信道。

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

### 3.3 用户会话模型：可见、可定向踢出

一次密码登录 = 一个刷新令牌**族** = 一个**会话**（`sessionId == fam`）。
同一个用户用不同客户端（例如 web 与只读端）分别登录，会得到**互不影响的多个会话**。

| 端点 | 说明 |
| --- | --- |
| `GET /api/sessions/{userId}` | 列出该用户**当前仍有效**的会话概览 |
| `DELETE /api/sessions/{userId}/{sessionId}` | **只注销指定的一个**会话，不牵连其它会话 |
| `DELETE /api/sessions/{userId}` | **一次性清空**该用户名下所有有效会话 |

- 这些端点都在 `/api/**` 下，需要 Bearer 认证 + `read` 作用域（列表）并通过主体校验：
  用户只能访问自己的会话路径，`ADMIN` 可管理任意用户。
- 会话概览字段：`sessionId`、`clientId`（来自哪个客户端）、`createdAt`（建立时间）、
  `lastUsedAt`（最近一次该会话访问令牌被使用的大致时间）、`expiresAt`；
  **不包含访问/刷新令牌原文**。
- 注销（单个/全部）作用于对应族：该会话**已经发出去的访问令牌在下一次请求时立即被拒**，
  错误码 `token_session_logged_out`（区别于族撤销的 `token_family_revoked`）。
  其它会话、以及执行注销操作的管理员自身的登录态都不受影响。
- 注销/撤销是幂等的：重复注销一个已结束会话返回 404 `session_not_found`；
  注销一个不属于该用户的会话返回 403 `forbidden_owner`。
- 「检查归属 → 标记注销 → 落盘」在存储层同一把锁内原子完成，
  因此并发注销同一会话**全进程最多生效一次**，其余得到稳定的 `session_not_found`。
- `lastUsedAt` 只是概览用的非关键信息：更新有秒级节流落盘；而注销、轮换、撤销等关键状态
  永远立即原子落盘，所以"最近使用时间"的轻微延迟绝不会影响注销的即时生效。

### 3.4 只读令牌自检（内部网关）

`POST /oauth/introspect`（RFC 7662 风格，不经过 `/api/**` 认证过滤器）：

```json
// 请求：先用客户端凭据认证调用方（内部网关），再给待检令牌
{ "client_id": "client-web", "client_secret": "web-secret", "token": "<访问令牌>" }
```

```jsonc
// 有效
{ "active": true, "subject": "u-alice", "clientId": "client-web",
  "sessionId": "…", "exp": 1700003600, "scope": ["read", "write"] }

// 无效（HTTP 仍是 200，用 active=false + reason 表达）
{ "active": false, "reason": "token_expired" }
```

- **只读、不改变状态**：不轮换、不撤销，也不更新会话 `lastUsedAt`；连续自检后令牌照常可用。
- 无效 `reason` 与受保护接口的错误码一一对应、彼此可区分：
  `missing_token` / `malformed_token` / `unsupported_alg` / `unknown_signing_key` /
  `bad_signature` / `missing_claims` / `token_expired` / `token_issuer_mismatch` /
  `token_session_logged_out` / `token_family_revoked` / `token_family_stale`。
- **乱填、空串、格式错误的令牌不会让服务抛异常**：一律收敛为 HTTP 200 + `active:false` + 对应 reason；
  请求体不是合法 JSON 时返回 400 `invalid_request`；客户端凭据错误返回 401 `invalid_client`。
- 响应**不回显令牌原文、不含任何密钥材料**（有效时只回主体、客户端、会话 ID、过期时间、作用域）。

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
| `GET /api/sessions/{userId}` | 作用域 `read` + 主体一致（ADMIN 豁免），见 §3.3 |
| `DELETE /api/sessions/{userId}/{sessionId}` | 主体一致（ADMIN 豁免），定向注销单会话 |
| `DELETE /api/sessions/{userId}` | 主体一致（ADMIN 豁免），清空该用户全部会话 |

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

### 6.1 多密钥平滑轮换（本地演示）

```bash
# 第一次启动：只有旧密钥 k-old，登录拿到旧令牌 OLD_AT
mvn spring-boot:run \
  --auth.security.signing-keys.k-old=old-secret-0123456789 \
  --auth.security.active-key-id=k-old
#   OLD_AT=$(... /oauth/token ...)

# 第二次启动：加入新密钥 k-new 并切为当前，但保留 k-old
mvn spring-boot:run \
  --auth.security.signing-keys.k-old=old-secret-0123456789 \
  --auth.security.signing-keys.k-new=new-secret-0123456789 \
  --auth.security.active-key-id=k-new
#   curl /api/ping -H "Authorization: Bearer $OLD_AT"   # 仍然 200（旧密钥还在，不掉线）
#   新登录得到的令牌头部 kid=k-new

# 第三次启动：摘掉 k-old（等旧访问令牌都到期后）
mvn spring-boot:run \
  --auth.security.signing-keys.k-new=new-secret-0123456789 \
  --auth.security.active-key-id=k-new
#   curl /api/ping -H "Authorization: Bearer $OLD_AT"   # 401 unknown_signing_key（立即失效）
```

### 6.2 会话查看与定向踢出

```bash
# alice 用两个客户端分别登录，得到 WEB_AT / RO_AT（互不影响）
# 列出 alice 当前有效会话（不返回令牌原文）
curl -s http://localhost:8080/api/sessions/u-alice -H "Authorization: Bearer $WEB_AT"
# SID=...（取返回里某个 sessionId）

# 只注销其中一个会话
curl -s -X DELETE http://localhost:8080/api/sessions/u-alice/$SID -H "Authorization: Bearer $WEB_AT"
# 该会话已发出的访问令牌立刻失效：401 token_session_logged_out
curl -s http://localhost:8080/api/ping -H "Authorization: Bearer $WEB_AT"
# 另一个会话照常可用：200
curl -s http://localhost:8080/api/ping -H "Authorization: Bearer $RO_AT"

# 一次性清空 alice 名下所有会话
curl -s -X DELETE http://localhost:8080/api/sessions/u-alice -H "Authorization: Bearer $RO_AT"
```

### 6.3 令牌自检

```bash
# 有效令牌
curl -s -X POST http://localhost:8080/oauth/introspect -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"client-web\",\"client_secret\":\"web-secret\",\"token\":\"$AT\"}"
#   {"active":true,"subject":"u-alice",...}

# 乱填的令牌：HTTP 200，active=false，不抛异常
curl -s -X POST http://localhost:8080/oauth/introspect -H 'Content-Type: application/json' \
  -d '{"client_id":"client-web","client_secret":"web-secret","token":"garbage"}'
#   {"active":false,"reason":"malformed_token"}

# 注销会话后再自检：reason=token_session_logged_out；自检本身不会把有效令牌变成无效
```

### 6.4 重启一致性

```bash
# 撤销族 / 注销会话后停止服务，再用同一密钥配置与默认状态文件重新启动
mvn spring-boot:run \
  --auth.security.signing-keys.k1=stable-key-0123456789 \
  --auth.security.active-key-id=k1
# ... 登录 -> /oauth/revoke 或 DELETE /api/sessions/... ...
# Ctrl-C 停止后以同样配置再次启动：
#   被撤销族的令牌依旧 token_family_revoked / invalid_grant_revoked；
#   被注销会话的令牌依旧 token_session_logged_out（不会退化为"未知"，也不会恢复可用）；
#   同主体未被注销的其它会话仍有效。
```

---

## 7. 测试

```bash
mvn test
```

共 72 个测试，全部可在无外部服务、无真实凭据条件下运行：

| 测试类 | 覆盖内容 |
| --- | --- |
| `MaskersTest` | 令牌/密钥脱敏不泄露原文、指纹稳定不可逆 |
| `AccessTokenServiceTest` | 过期、载荷/签名篡改、`none`/异算法、缺声明、签发者不符、同环异密钥——错误码逐一区分 |
| `SigningKeyRingTest` | **多密钥签发/验签、旧密钥保留仍可验、摘除即 unknown、kid 在环但签名错为 bad、启动 fail-fast、临时密钥** |
| `RefreshTokenStoreTest` | 轮换、32 线程并发恰一次成功、未知/客户端不符/过期/撤销可区分、状态文件只含哈希、重启重载 |
| `SessionServiceTest` | **多客户端独立会话、定向注销不牵连其它、批量注销按主体隔离、归属/not-found 区分、32 线程并发恰一次注销、重启保持** |
| `TokenIntrospectionServiceTest` | **自检有效载荷、只读不变更（不轮换/不更新 lastUsedAt）、8 种乱填输入不抛异常、过期/注销/撤销/篡改/密钥摘除原因区分** |
| `RateLimitServiceTest` | 固定窗口上限、主体隔离、窗口翻转、500 线程恰好不超量 |
| `AuthFlowIntegrationTest` | 全栈：登录、缺/畸形令牌、篡改、主体不符、角色、作用域、归属、刷新轮换与重放、撤销 |
| `KeyRotationIntegrationTest` | **三个真实 Spring 上下文：旧密钥签发 → 新旧并存旧令牌仍可用 → 摘除旧密钥立即 unknown，新令牌不受影响** |
| `SessionAndIntrospectionIntegrationTest` | **HTTP 会话列表（不泄露令牌原文）/定向踢出/批量清空/管理员代管、自检端点有效与各类无效、坏 JSON、客户端鉴权** |
| `SessionPersistenceRestartTest` | **两个真实上下文：会话注销后重启仍是 token_session_logged_out、自检结论一致、同主体其它会话存活** |
| `RateLimitIntegrationTest` | HTTP 端到端恰好 10 个通过、第 11 个 429 |
| `ExpiryIntegrationTest` | 可控时钟推进后访问令牌 `token_expired`（无需真实等待） |
| `RefreshExpiryIntegrationTest` | 刷新族过期 `invalid_grant_expired` |
| `PersistenceRestartTest` | 真实创建/关闭两个 Spring 上下文读写同一文件，验证重启后撤销结论一致 |

令牌过期类测试通过可替换的 `Clock` Bean 推进时间，结论确定、无需睡眠。
密钥轮换 / 会话重启类测试通过手动启停多个真实 Spring 上下文（载入不同密钥配置、共享状态文件）完成。

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
| `AUTH_HMAC_KEY` / `auth.security.hmacKey` | 内置本地开发占位值 | 单密钥兼容模式的 HMAC 密钥（= kid `default`）；不落盘 |
| `auth.security.signingKeys.<id>` | 空 | 多密钥轮换：keyId 到密钥原文的映射，可配置多把；密钥只来自配置且不落盘 |
| `auth.security.activeKeyId` / `AUTH_ACTIVE_KEY_ID` | 空 | 当前**签发**密钥的 ID，必须是 `signingKeys` 中的一个；多密钥模式必填 |
| `auth.security.issuer` | `local-auth-service` | 令牌签发者，校验 `iss` |
| `auth.token.accessTtlSeconds` | `600` | 访问令牌有效期 |
| `auth.token.refreshTtlSeconds` | `1209600` | 刷新令牌族有效期（14 天） |
| `auth.token.stateFile` | `data/refresh-state.json` | 族/会话状态文件（仅哈希、代际、注销标记、会话时间戳） |
| `auth.ratelimit.maxRequests` | `10` | 每主体每窗口上限 |
| `auth.ratelimit.windowSeconds` | `60` | 限流窗口长度 |

---

## 10. 兼容范围与重启行为

**向后兼容**

- 旧的单密钥配置 `AUTH_HMAC_KEY` / `auth.security.hmac-key` 继续可用，行为与上一版本一致；
  旧版本签发、头部没有 `kid` 的令牌按密钥 id `default` 校验。
- 多密钥与单密钥两种模式只取其一：配置了任意 `signing-keys` 即进入多密钥模式，
  此时必须显式给出 `active-key-id`，指向不存在的 ID 会在启动时失败（fail-fast）。
- 刷新令牌族状态文件格式向后兼容：旧文件没有 `lastUsedAt` / `logoutReason` 字段时按默认值
  （`lastUsedAt=0`，概览展示时回退为建立时间；注销原因为 `NONE`）读取，不会导致启动失败。

**进程重启后的表现**（使用同一密钥配置与同一状态文件）

| 对象 | 重启后结论 |
| --- | --- |
| 有效、未注销的会话/族 | 继续有效，访问令牌与刷新令牌照常使用 |
| 被定向/批量注销的会话 | 仍是 `token_session_logged_out`，不会变"未知"，也不会恢复 |
| 被撤销的族 | 仍是 `token_family_revoked` / `invalid_grant_revoked` |
| 已轮换掉的旧刷新令牌 | 仍是 `invalid_grant_replayed` |
| 由仍保留密钥签发的未到期令牌 | 验签通过（平滑轮换期间不掉线） |
| 由已摘除密钥签发的令牌 | `unknown_signing_key`，立即失效 |
| 未配置密钥（临时随机密钥）时重启 | 旧令牌验签失败（预期，仅临时调试） |
