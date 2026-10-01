# 本地认证与访问控制服务（Java / Spring Boot）

一套**完全本地运行**的 Web 服务，演示并验证完整的认证与访问控制流程：

- 访问令牌（自描述 JWT，HS256）的**签发与校验**；
- 签名密钥的**平滑轮换**：多把密钥并存、指定当前签发密钥，旧密钥摘除即失效；
  「密钥未知/已摘除」与「签名对不上」是两个不同结论；
- 刷新令牌的**轮换（rotation）与撤销（revocation）**，并发/重复使用时**全进程最多成功一次**；
- **用户会话可见、可定向踢除**：按用户列出会话概览、注销单个或全部会话，注销即时生效，重启一致；
  重复或并发注销同一会话**恰好一次成功**，其余明确告知会话不存在/已注销；
- 面向内网网关的**只读令牌自检入口**（RFC 7662 风格），细分各类无效原因：
  没带令牌也返回 200 + 原因，且「令牌被撤销」(`token_revoked`) 与「会话被注销」
  (`session_revoked`) 明确可分；
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

### 1.1 签名密钥与平滑轮换（重要）

访问令牌的 HMAC 密钥**只能来自配置**，程序不会把它写入任何文件。支持两种互斥的配置方式：

**方式一：多命名密钥 + 当前签发密钥（推荐，支持平滑轮换）**

```properties
# 配置若干把密钥，键名是自定义的密钥 ID（kid），值是密钥
auth.security.keys.k1=旧密钥原文
auth.security.keys.k2=新密钥原文
# 指定当前用来“签发”新令牌的那一把
auth.security.active-key-id=k2
```

- 新签发的令牌头部带 `{"alg":"HS256","typ":"JWT","kid":"k2"}`，验签时按令牌头部的 `kid`
  在配置中定位对应密钥。
- **轮换流程（无掉线）**：
  1. 把新密钥（如 `k2`）加进 `keys`，并把 `active-key-id` 指向 `k2`；**旧密钥 `k1` 先保留**。
     此后新令牌走 `k2`；线上尚未到期、由 `k1` 签出的令牌继续通过校验。
  2. 等旧令牌自然到期（或确认无在线用户持有）后，把 `k1` 从 `keys` 中摘掉并重启/重新加载配置。
     **摘除瞬间**，所有仍由 `k1` 签出的令牌立即失效，返回 `unknown_signing_key`。
- 两种验签失败严格区分：
  - 令牌的 `kid` 在当前配置中不存在（不认识或已摘除）→ `unknown_signing_key`；
  - `kid` 认识但 HMAC 对不上（载荷/签名被篡改）→ `bad_signature`。
- 启动期校验：多密钥与旧单密钥同时配置、`active-key-id` 不在 `keys` 中、存在空密钥等
  二义/非法配置会在启动时直接失败（fail-fast），不会静默使用错误密钥。

**方式二：旧式单密钥（兼容既有部署）**

```properties
auth.security.hmac-key=${AUTH_HMAC_KEY:local-development-only-hmac-key-please-change}
```

通过环境变量 `AUTH_HMAC_KEY` 注入即可；该模式签发的令牌头部不带 `kid`，验签回退用这把唯一密钥。

> 两种方式都未配置时，进程会在**内存中用 SecureRandom 生成一次性随机密钥**并打印 WARN，
> 功能正常但**重启后此前签发的令牌必然验签失败**——仅适合临时调试。
> 多密钥值同样建议用环境变量/启动参数注入（如 `--auth.security.keys.k1=...`），不要写进镜像。

刷新令牌的撤销/轮换/会话状态需要跨重启保持，因此会写入本地状态文件
（默认 `data/refresh-state.json`，已在 `.gitignore` 中忽略）。
文件里**只有刷新令牌的 SHA-256 哈希、代际号、撤销标记与会话元数据时间戳，没有任何明文令牌或密钥**。

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
| 3 | 头部 `kid` 在配置中不存在（不认识/已摘除） | 401 | `unknown_signing_key` |
| 3 | 密钥认识但签名不匹配（载荷/签名被篡改） | 401 | `bad_signature` |
| 4 | 缺少任一必需声明或声明为空 | 401 | `missing_claims` |
| 5 | `exp` 已到期 | 401 | `token_expired` |
| 6 | `iss` 与本服务配置不符 | 401 | `token_issuer_mismatch` |
| 7 | 令牌所属族/会话已被撤销或注销 | 401 | `token_family_revoked` |
| 7 | 令牌属于被轮换掉的旧代 / 族未知 | 401 | `token_family_stale` |
| 8 | 令牌主体与请求资源不符（见 §4） | 401 | `token_subject_mismatch` |

签名比较使用 `MessageDigest.isEqual`（常量时间），避免计时侧信道。
`unknown_signing_key` 与 `bad_signature` 在签名段比对**之前**就分流，语义互不混淆。

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

### 3.3 用户会话模型：可见、可定向踢除

一次授权（密码登录）创建一个刷新令牌**族**，也就是一个**会话**。同一用户在不同客户端、
或多次登录，会得到互不影响的多个会话（族）。在族模型之上提供了面向运维的会话管理能力：

| 端点（均在 `/api/**`，需 ADMIN 角色） | 作用域 | 说明 |
| --- | --- | --- |
| `GET  /api/admin/sessions/{userId}` | `read` | 列出该用户**当前有效**会话概览 |
| `POST /api/admin/sessions/{userId}/{sessionId}` | `write` | **定向注销**单个会话 |
| `POST /api/admin/sessions/{userId}` | `write` | 一次性注销该用户**全部**有效会话 |

会话概览字段（`SessionOverview`）：

| 字段 | 含义 |
| --- | --- |
| `sessionId` | 会话 ID（即族 ID，非秘密，可用于定向注销） |
| `subject` | 会话主体（用户 ID） |
| `clientId` | 来自哪个客户端 |
| `createdAt` | 会话建立时间（epoch 秒） |
| `lastUsedAt` | 最近使用时间（epoch 秒，概览值） |
| `expiresAt` | 会话到期时间（epoch 秒） |

关键语义：

- 概览**不暴露任何访问/刷新令牌原文**，只有元数据。
- **定向注销只影响目标会话**，同一用户的其它会话不受牵连；注销底层即「撤销该族」，
  因此该会话**此前已发出的访问令牌也立即失效**（受保护请求返回 `token_family_revoked`，
  自检返回 `active:false, reason=session_revoked`）。
- **重复 / 并发注销同一会话恰好成功一次**：「归属与存在性检查 + 撤销 + 落盘」在存储层同一把锁内
  原子完成，因此无论串行重复还是多请求并发，只有一个请求返回 `200 {"status":"revoked"}`，
  其余全部返回 404 `session_not_found`（会话不存在、已注销或已过期）——不会出现「两次都成功」。
  跨主体注销别人的会话也按 `session_not_found` 处理，不向调用方泄露会话归属。
- 「注销全部」只统计并返回本次实际注销的数量（重复调用返回 `revoked:0`），并发下每个会话只计一次。
- 对不存在/已过期/已注销的会话再次注销，返回 404 `session_not_found`；
  会话不属于该 `userId` 时同样按 `session_not_found` 处理，不向调用方泄露归属。
- `lastUsedAt` 仅用于展示：访问令牌通过认证、刷新成功都会更新它。为避免每个 API 请求都写盘，
  落盘做了约 60 秒节流（内存中实时、磁盘上近似），**它不参与任何安全判定**。
- **重启一致性**：会话与撤销状态随族状态一起持久化（见 §3.2）。重启后，已建立且未过期的会话
  仍可列出；被注销的会话仍保持注销（`session_not_found` / 访问令牌 `token_family_revoked`），
  不会退化成「未知」或「好像没发生过」。

### 3.4 只读令牌自检（面向内网网关）

`POST /oauth/introspect`（RFC 7662 风格），供内部网关在放行前查询令牌当前状态。
需要先用客户端凭据认证（与 `/oauth/revoke` 一致，不允许匿名探测）：

```json
{ "client_id": "client-web", "client_secret": "web-secret", "token": "<访问令牌>" }
```

有效响应：

```json
{ "active": true, "sub": "u-alice", "client_id": "client-web", "exp": 1700000600, "scope": "read write" }
```

无效响应一律是 **HTTP 200 + `active:false`**（不抛 4xx/5xx，网关按 200 解析即可），
并用 `reason` 区分类别：

| reason | 含义 |
| --- | --- |
| `missing_token` | 没带 token（字段缺失、为 null、空串或纯空白）——仍返回 **200**，不是参数错误 |
| `malformed` | 乱填/结构/编码/JSON 无法解析 |
| `unsupported_alg` | `alg` 不是 HS256（含 `none`） |
| `bad_signature` | 密钥认识但签名对不上（被篡改） |
| `unknown_signing_key` | 由不认识的/已摘除的密钥签发 |
| `missing_claims` | 缺少必需声明 |
| `expired` | 已过期 |
| `issuer_mismatch` | 签发者不符 |
| `token_revoked` | 令牌本身被显式撤销（`/oauth/revoke`） |
| `session_revoked` | 令牌所属会话被注销/踢下线（单个或全部注销） |
| `family_stale` | 属于被轮换掉的旧代，或族已过期/未知 |

> **`token_revoked` 与 `session_revoked` 是两个互不混淆的原因**：撤销起因随族状态一起持久化
> （令牌端点撤销记为令牌撤销，会话管理端点注销记为会话注销；重启后结论不变）。
> 网关可据此采取不同策略（例如前者只拉黑该令牌，后者提示用户重新登录）。
> 历史版本落盘、没有起因字段的已撤销记录按 `token_revoked` 解释。

**没带令牌时的返回约定**：只要客户端凭据有效，无论 `token` 字段缺失、为 `null`、空串还是纯空白，
都返回 `200 {"active":false,"reason":"missing_token"}`，**不会**返回 4xx，也不回显令牌原文。
乱填、格式不对的令牌同理，一律 200 + 对应 `reason`。
（请求体整体缺失/不是合法 JSON、或 `client_id`/`client_secret` 缺失错误仍分别返回 400/401。）

性质：该入口**只读**——不轮换、不撤销、不更新 `lastUsedAt`，多次自检不改变令牌有效性；
客户端凭据错误返回 401 `invalid_client`；响应**不回显令牌原文、不泄露任何签名密钥**。

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
| `GET /api/admin/sessions/{userId}` | 角色 `ADMIN` + 作用域 `read`（见 §3.3） |
| `POST /api/admin/sessions/{userId}/{sessionId}` | 角色 `ADMIN` + 作用域 `write` |
| `POST /api/admin/sessions/{userId}` | 角色 `ADMIN` + 作用域 `write` |

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

# 12) 只读自检：有效令牌
curl -s -X POST http://localhost:8080/oauth/introspect -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"client-web\",\"client_secret\":\"web-secret\",\"token\":\"$AT\"}"
# -> {"active":true,"sub":"u-alice",...}
# 乱填令牌 -> 200 {"active":false,"reason":"malformed"}；篡改 -> reason=bad_signature

# 12b) 没带令牌（字段缺失 / 为空）：同样是 200，而不是 4xx
curl -i -X POST http://localhost:8080/oauth/introspect -H 'Content-Type: application/json' \
  -d '{"client_id":"client-web","client_secret":"web-secret"}'
# -> HTTP/1.1 200  {"active":false,"reason":"missing_token"}

# 12c) 令牌被显式撤销 vs 会话被注销：两个不同原因
#   /oauth/revoke 后自检      -> {"active":false,"reason":"token_revoked"}
#   会话管理端点注销后自检    -> {"active":false,"reason":"session_revoked"}

# 13) 会话管理（用 admin 登录拿管理令牌 ADMIN_AT）
ADMIN_RESP=$(curl -s -X POST http://localhost:8080/oauth/token -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"client-web","client_secret":"web-secret",
       "username":"admin","password":"admin-pass-123"}')
ADMIN_AT=$(echo "$ADMIN_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 列出 alice 当前有效会话（不含令牌原文）
curl -s http://localhost:8080/api/admin/sessions/u-alice -H "Authorization: Bearer $ADMIN_AT"

# 定向注销其中一个会话（把 <sid> 换成上一步返回的 sessionId）
curl -s -X POST http://localhost:8080/api/admin/sessions/u-alice/<sid> \
  -H "Authorization: Bearer $ADMIN_AT"
# 注销后该会话的访问令牌：401 token_family_revoked；自检：active=false,reason=session_revoked

# 对同一个 <sid> 再注销一次（或并发同时注销）：只有一次 200，其余 404 session_not_found
curl -i -X POST http://localhost:8080/api/admin/sessions/u-alice/<sid> \
  -H "Authorization: Bearer $ADMIN_AT"
# -> HTTP/1.1 404  {"error":"session_not_found", ...}

# 一次性注销 alice 全部会话
curl -s -X POST http://localhost:8080/api/admin/sessions/u-alice \
  -H "Authorization: Bearer $ADMIN_AT"
```

### 6.2 密钥平滑轮换（本地验证）

```bash
# 阶段一：两把密钥都在配置里，active=k1；登录拿到旧令牌 AT_OLD
java -jar app.jar \
  --auth.security.hmacKey= \
  '--auth.security.keys.k1=secret-key-one' \
  '--auth.security.keys.k2=secret-key-two' \
  --auth.security.active-key-id=k1
#   （用 --auth.security.hmacKey= 显式清空默认单密钥，避免二义配置）

# 阶段二：active 切到 k2，但保留 k1（重启/重载配置）
#   AT_OLD 仍能访问 /api/ping（200）；新登录的令牌走 k2

# 阶段三：摘掉 k1，只留 k2
java -jar app.jar --auth.security.hmacKey= \
  '--auth.security.keys.k2=secret-key-two' --auth.security.active-key-id=k2
#   AT_OLD 立刻 401 unknown_signing_key；k2 签发的令牌仍 200
#   对比：把令牌签名最后一位改掉则是 401 bad_signature
```

### 6.1 重启一致性

```bash
# 撤销一个族 / 注销会话后停止服务，再重新启动（使用同一个 AUTH_HMAC_KEY 与默认状态文件）
AUTH_HMAC_KEY="stable-key" mvn spring-boot:run
# ... 登录 -> /oauth/revoke 或 POST /api/admin/sessions/{userId}/{sessionId} ...
# Ctrl-C 停止后再次 AUTH_HMAC_KEY="stable-key" mvn spring-boot:run
# 此前被撤销族的令牌依旧返回 token_family_revoked / invalid_grant_revoked；
# 被注销的会话依旧为已注销（session_not_found），未注销会话仍可列出、令牌仍可用。
```

> 兼容范围：会话/撤销状态依赖本地状态文件保持；跨重启验签则要求签名密钥保持不变
> （多密钥模式下对应 kid 仍在配置中，或单密钥模式下 `AUTH_HMAC_KEY` 不变）。
> `lastUsedAt` 为概览值，落盘有约 60 秒节流，极端情况下重启后可能回退到上一次落盘值，
> 这不影响任何安全结论。

---

## 7. 测试

```bash
mvn test
```

共 72 个测试，全部可在无外部服务、无真实凭据条件下运行：

| 测试类 | 覆盖内容 |
| --- | --- |
| `MaskersTest` | 令牌/密钥脱敏不泄露原文、指纹稳定不可逆 |
| `AccessTokenServiceTest` | 过期、载荷/签名篡改、`none`/异算法、缺声明、签发者不符、异密钥——错误码逐一区分 |
| `SigningKeyRotationTest` | 多密钥签发带 kid、轮换期间旧密钥兼容、摘除旧密钥即 `unknown_signing_key`、与 `bad_signature` 区分、非法多密钥配置 fail-fast |
| `RefreshTokenStoreTest` | 轮换、32 线程并发恰一次成功、未知/客户端不符/过期/撤销可区分、状态文件只含哈希、重启重载、撤销起因持久化与历史记录兼容 |
| `SessionConcurrencyTest` | 多客户端登录形成独立会话、32 线程并发注销单个会话**恰好一次成功**、并发注销全部对每个会话仅一次、不牵连他人/其它主体、跨主体注销被拒 |
| `SessionServiceTest` | 经服务层重复/并发注销：一次成功其余 `session_not_found`、空白 sessionId 400、被注销会话访问令牌立即失效 |
| `IntrospectionServiceTest` | 自检有效/无效（畸形、过期、篡改、未知族、`unknown_signing_key`、`unsupported_alg`）原因区分、**`token_revoked` 与 `session_revoked` 分开**、乱填不抛异常、只读不改状态 |
| `RateLimitServiceTest` | 固定窗口上限、主体隔离、窗口翻转、500 线程恰好不超量 |
| `AuthFlowIntegrationTest` | 全栈：登录、缺/畸形令牌、篡改、主体不符、角色、作用域、归属、刷新轮换与重放、撤销 |
| `KeyRotationIntegrationTest` | 真实多上下文：k1→k2 切换保留 k1 旧令牌可用、摘掉 k1 立即 `unknown_signing_key` |
| `SessionAdminIntegrationTest` | 会话列表不含令牌原文、定向注销即时失效、全部注销、**HTTP 层 16 线程并发注销同一会话恰好一次 200/其余 404**、自检端到端各类原因、**没带令牌（缺失/null/空/空白）一律 200 + missing_token**、匿名自检 401 |
| `SessionRestartTest` | 真实双上下文：重启后会话仍在、已注销保持注销、旧令牌依旧 `token_family_revoked` |
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
| `AUTH_HMAC_KEY` / `auth.security.hmacKey` | 内置本地开发占位值 | 旧式单密钥（兼容模式）；不落盘。与 `keys` 互斥 |
| `auth.security.keys.<kid>` | — | 多密钥轮换模式：命名密钥集合，kid 为自定义标识；不落盘 |
| `auth.security.active-key-id` | — | 多密钥模式下当前用于签发的 kid，必须存在于 `keys` |
| `auth.security.issuer` | `local-auth-service` | 令牌签发者，校验 `iss` |
| `auth.token.accessTtlSeconds` | `600` | 访问令牌有效期 |
| `auth.token.refreshTtlSeconds` | `1209600` | 刷新令牌族/会话有效期（14 天） |
| `auth.token.stateFile` | `data/refresh-state.json` | 族/会话状态文件（仅哈希/标记/时间戳） |
| `auth.ratelimit.maxRequests` | `10` | 每主体每窗口上限 |
| `auth.ratelimit.windowSeconds` | `60` | 限流窗口长度 |
