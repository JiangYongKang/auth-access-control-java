# 本地认证与访问控制服务（Spring Boot）

一个完全本地运行、不依赖任何外部服务的认证与访问控制示例：用本地配置模拟用户/客户端，
用内存状态 + 本地 JSON 文件管理令牌状态，令牌生命周期、权限判定、限流在并发与异常输入下
都给出**可区分、可复现**的结论。

- Java 21+ / Spring Boot 3.4 / 无数据库、无外部 IdP
- 访问令牌：自包含 HMAC-SHA256 令牌（非 JWT 库），声明齐全才接受
- 刷新令牌：家族（family）模型 + 原子轮换 + 重放检测 + 撤销，状态落盘，重启结论一致
- 访问控制：角色 / 作用域 / 资源归属三类判定，拒绝原因可区分
- 限流：每主体滑动窗口，key 级锁严格保证高并发不放行超量请求

## 1. 快速开始

```bash
mvn spring-boot:run          # 默认 8080
mvn test                     # 26 个测试，无需任何外部服务或真实凭据
```

> 本地开发凭据（仅用于本地联调，**未写入配置文件**）：
>
> | 类型 | 标识 | 凭据 | 角色 / 作用域 |
> |---|---|---|---|
> | 用户 | `alice` | `alice-pw` | ADMIN, USER |
> | 用户 | `bob` | `bob-pw` | USER |
> | 客户端 | `webapp` | `webapp-secret` | profile:read, admin:read, doc:read |
> | 客户端 | `reader` | `reader-secret` | profile:read, doc:read |
>
> 配置文件中保存的只是 PBKDF2 哈希；生产环境请替换为自己的凭据与密钥。

## 2. 密钥与凭据如何保存（敏感信息保护）

| 敏感项 | 保存形式 | 说明 |
|---|---|---|
| HMAC 签名密钥 | **Base64 编码**配置项 `auth.token.key-base64` | 不以明文形式落盘；可用环境变量 `AUTH_TOKEN_KEY_BASE64` 覆盖；启动时解码到内存，长度需 ≥ 256 bit |
| 用户口令 | PBKDF2-HmacSHA256（120k 轮、随机盐） | 配置只存 `pbkdf2$iter$salt$dk`，使用恒定时间比较 |
| 客户端密钥 | 同上 PBKDF2 | 同上 |
| 刷新令牌 | 只存 **SHA-256 指纹** | 原始令牌只在签发响应中出现一次；状态文件泄露也无法还原令牌 |
| 日志 | 敏感字段脱敏 | 令牌/口令证据经 `SensitiveLog` 只保留前 4 字符与长度 |

令牌状态文件默认 `data/token-state.json`（可用 `AUTH_TOKEN_STORE_PATH` 覆盖），已在
`.gitignore` 中忽略；写入采用「临时文件 + FileLock + 原子 move」。

## 3. HTTP 接口

### 3.1 获取令牌（密码授权）

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -d 'grant_type=password' \
  -d 'client_id=webapp&client_secret=webapp-secret' \
  -d 'username=alice&password=alice-pw' \
  -d 'scope=profile:read doc:read admin:read'
```

响应：`access_token` / `refresh_token` / `token_type=Bearer` / `access_jti` / `scope`。

### 3.2 刷新（轮换）

```bash
curl -s -X POST http://localhost:8080/oauth/token \
  -d 'grant_type=refresh_token' \
  -d 'client_id=webapp&client_secret=webapp-secret' \
  -d 'refresh_token=<上一次返回的 refresh_token>'
```

### 3.3 撤销 / 登出

```bash
curl -s -X POST http://localhost:8080/oauth/revoke \
  -d 'client_id=webapp&client_secret=webapp-secret' \
  -d 'token=<refresh_token>'
```

### 3.4 受保护资源

| 接口 | 要求 |
|---|---|
| `GET /api/profile` | 有效 Bearer 令牌 + scope `profile:read` |
| `GET /api/admin` | 角色 `ADMIN` **且** scope `admin:read` |
| `GET /api/documents/{id}` | scope `doc:read` **且**文档归属当前用户（`auth.documents.*`） |

```bash
curl -s -H "Authorization: Bearer <access_token>" http://localhost:8080/api/profile
```

## 4. 令牌生命周期模型

### 4.1 访问令牌

格式：`base64url(JSON payload) + '.' + hex(HMAC_SHA256(payload))`，payload 必含
`jti, sub, cid, iss, aud, roles, scopes, iat, exp`。

校验顺序（每一步失败都返回**不同 reason**）：

1. `MISSING_AUTHORIZATION`：受保护请求无 Authorization 头
2. `MALFORMED`：不是 `Bearer xxx`、结构错误、payload 无法解析、签名不是合法十六进制
3. `SIGNATURE_INVALID`：格式合法但签名不匹配（被篡改），恒定时间比较
4. `MISSING_REQUIRED_CLAIM`：缺少任一必需声明或声明为空
5. `ISSUER_MISMATCH` / `AUDIENCE_MISMATCH`：签发主体与当前服务配置不符
6. `EXPIRED`：`exp <= now`
7. `TOKEN_DENIED`：jti 在拒绝清单（刷新轮换或撤销后，旧访问令牌立即失效）

HTTP 状态码为 `401`，响应体形如：

```json
{ "error": "invalid_token", "reason": "SIGNATURE_INVALID" }
```

### 4.2 刷新令牌：家族、轮换、重放检测与撤销

- 每次密码授权创建一个**家族（family）**，家族内形成 refresh token 链；
  服务端只保存每个令牌的 SHA-256 指纹、状态（`ACTIVE/ROTATED/REVOKED`）与到期时间。
- **轮换是原子操作**（同一把状态锁内完成「校验 → 旧令牌置 ROTATED →
  旧 access jti 加入拒绝清单 → 登记新 refresh/access」，随后原子落盘）：
  并发或重复使用同一刷新令牌时，**最多一次成功**。
- 对已 ROTATED 的令牌再次使用：
  - 在宽限窗口（`auth.refresh.grace-window`）内 → `CONCURRENT_REUSE`（并发竞争输家）；
  - 超出宽限窗口 → `REPLAYED`，判定为重放攻击，**整个家族立即撤销**。
- 主动 `/oauth/revoke` → 家族撤销，链上全部 refresh token 与当前 access token 立即失效
  （`REVOKED`）。
- 其它可区分原因：`NOT_FOUND`（不存在/乱码）、`EXPIRED`、`CLIENT_MISMATCH`
  （刷新请求的客户端与家族客户端不同）。
- 状态变更每次都写入 `data/token-state.json`：**进程重启后撤销/重放结论保持一致**。

```
 password grant ──▶ family: RT1(ACTIVE)+AT1
 rotate RT1       ──▶ RT1(ROTATED), AT1 jti→denylist, RT2(ACTIVE)+AT2
 reuse RT1 (窗口内) ─▶ 400 CONCURRENT_REUSE
 reuse RT1 (窗口外) ─▶ 400 REPLAYED + family REVOKED（AT2 同时失效）
 revoke RT*        ─▶ family REVOKED + 当前 AT 失效
```

## 5. 权限模型

判定全部在服务端完成，三类拒绝原因互不混淆（HTTP 403）：

| reason | 触发条件 |
|---|---|
| `MISSING_ROLE` | 令牌角色集合与接口要求无交集（如普通用户访问 `/api/admin`） |
| `INSUFFICIENT_SCOPE` | 缺少接口要求的全部/任一 scope（如 `reader` 客户端访问 admin） |
| `RESOURCE_OWNER_MISMATCH` | 资源不存在或资源属主不等于令牌 `sub` |

scope 在令牌签发时按「客户端被授予的 scope」与「请求 scope」的交集发放，
请求超出客户端授权范围时令牌端点返回 `invalid_scope`。

## 6. 限流模型

- 维度：主体 `sub@cid`，与客户端 IP 无关；
- 算法：滑动日志窗口（`auth.rate-limit.window-requests` / `auth.rate-limit.window`）；
- 并发正确性：每个 key 一把锁，「清理过期请求 → 计数 → 占位」在锁内一次完成，
  高并发下放行数**恒等于配额**，不会多放；
- 超限：HTTP `429`，`{ "error":"rate_limit_exceeded", "reason":"TOO_MANY_REQUESTS" }`，
  带 `Retry-After` 头。

## 7. 错误原因速查

| 场景 | HTTP | error | reason |
|---|---|---|---|
| 无 Authorization | 401 | invalid_token | MISSING_AUTHORIZATION |
| 头/令牌畸形 | 401 | invalid_token | MALFORMED |
| 签名被篡改 | 401 | invalid_token | SIGNATURE_INVALID |
| 缺必需声明 | 401 | invalid_token | MISSING_REQUIRED_CLAIM |
| iss / aud 不符 | 401 | invalid_token | ISSUER_MISMATCH / AUDIENCE_MISMATCH |
| 令牌过期 | 401 | invalid_token | EXPIRED |
| 轮换/撤销后旧令牌 | 401 | invalid_token | TOKEN_DENIED |
| 刷新：不存在 | 400 | invalid_grant | NOT_FOUND |
| 刷新：过期 | 400 | invalid_grant | EXPIRED |
| 刷新：已撤销 | 400 | invalid_grant | REVOKED |
| 刷新：并发复用 | 400 | invalid_grant | CONCURRENT_REUSE |
| 刷新：重放攻击 | 400 | invalid_grant | REPLAYED |
| 刷新：客户端不符 | 400 | invalid_grant | CLIENT_MISMATCH |
| 客户端认证失败 | 401 | invalid_client | INVALID_CLIENT |
| 用户认证失败 | 401 | invalid_grant | INVALID_GRANT |
| 越权（角色/作用域/归属） | 403 | access_denied | MISSING_ROLE / INSUFFICIENT_SCOPE / RESOURCE_OWNER_MISMATCH |
| 超频 | 429 | rate_limit_exceeded | TOO_MANY_REQUESTS |

## 8. 本地手工验证（curl 剧本）

```bash
BASE=http://localhost:8080

# 1) 密码授权
TOK=$(curl -s -X POST $BASE/oauth/token \
  -d 'grant_type=password&client_id=webapp&client_secret=webapp-secret' \
  -d 'username=alice&password=alice-pw&scope=profile:read doc:read admin:read')
AT=$(echo "$TOK" | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
RT=$(echo "$TOK" | sed 's/.*"refresh_token":"\([^"]*\)".*/\1/')

# 2) 正常访问
curl -s -H "Authorization: Bearer $AT" $BASE/api/profile

# 3) 篡改（翻转签名首字符）→ SIGNATURE_INVALID
curl -s -H "Authorization: Bearer ${AT%??}$(echo $AT | tail -c2 | tr a-f b-fa-e)" $BASE/api/profile

# 4) 刷新轮换
R2=$(curl -s -X POST $BASE/oauth/token \
  -d "grant_type=refresh_token&client_id=webapp&client_secret=webapp-secret&refresh_token=$RT")
# 5) 旧 refresh 重放 → REPLAYED（家族撤销）
curl -s -X POST $BASE/oauth/token \
  -d "grant_type=refresh_token&client_id=webapp&client_secret=webapp-secret&refresh_token=$RT"
# 6) 旧 access 已失效 → TOKEN_DENIED
curl -s -H "Authorization: Bearer $AT" $BASE/api/profile
```

## 9. 测试

```bash
mvn test
```

- `TokenServiceTest`：合法令牌、过期、签名/载荷篡改、iss/aud 不符、缺声明、畸形输入、jti 拒绝清单；
- `FileTokenStateStoreTest`：单次轮换、顺序重放（REPLAYED + 家族撤销）、
  **20 线程并发轮换恰好一次成功**、主动撤销及**重启后结论一致**、过期/不存在/客户端不符区分；
- `SlidingWindowRateLimiterTest`：恰好放到配额、窗口滑动、key 隔离、
  **200 并发请求恰好放行配额数**；
- `EndToEndWebTest`：真实 HTTP 全链路（含 20 路并发刷新）、角色/作用域/归属三类拒绝、429 限流；
- `SensitiveLogTest`：日志脱敏不泄漏令牌主体。

测试使用 `src/test/resources/application.properties`（2 秒短 TTL、配额 3、
独立状态文件 `target/test-data/`），全部随机生成哈希与签名密钥，无外部服务、无真实凭据。

## 10. 配置项

| 配置 | 默认 | 含义 |
|---|---|---|
| `auth.token.key-base64` | 内置开发值（请覆盖） | HMAC 密钥的 Base64；`AUTH_TOKEN_KEY_BASE64` 可覆盖 |
| `auth.token.issuer` / `audience` | local-auth / local-api | 签发主体，不符即拒绝 |
| `auth.token.ttl` | 30m | 访问令牌有效期 |
| `auth.refresh.ttl` | 7d | 刷新令牌有效期 |
| `auth.refresh.grace-window` | 100ms | 并发复用 vs 重放的判定窗口 |
| `auth.refresh.store-path` | data/token-state.json | 持久化状态文件 |
| `auth.rate-limit.window-requests` | 100 | 窗口配额 |
| `auth.rate-limit.window` | 1m | 限流窗口 |
| `auth.users[i].*` | 2 个示例用户 | 用户名 + PBKDF2 口令哈希 + 角色 |
| `auth.clients[i].*` | 2 个示例客户端 | clientId + PBKDF2 密钥哈希 + scopes |
| `auth.documents.<id>` | 2 个示例文档 | 资源属主映射 |
