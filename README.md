# 本地密钥托管与租约访问（Local Managed Keys + Short-lived Leases）

用**本地密钥材料**模拟受管密钥（KMS），在一个 Spring Boot 进程内实现：
密钥版本引入与轮换、按主体/作用域签发的短期租约、以及覆盖全部敏感动作的审计。
所有入口（HTTP API、测试）都经由同一个服务门面 `SecretService`，因此结论一致、原因可区分、可解释。

## 1. 密钥版本与轮换、宽限策略

- 初始密钥版本为 **v1**（AES-256/GCM，随机 IV，128 位认证标签）。每次轮换生成全新密钥，版本号 **+1**。
- 密文是自描述信封：`mlcv1:<keyVersion>:<base64(iv)>:<base64(ciphertext)>`，携带加密时的版本。
- **宽限期**（`app.grace-period`，默认 `PT2M`）：旧版本被新版本取代的时刻记为 `retiredAt`，
  这是宽限计时的**唯一起点**（多次轮换不会延长更老版本的宽限期）。
  - `now < retiredAt + grace`：旧版本密文**仍可解密**；
  - `now >= retiredAt + grace`：旧版本被**明确拒绝**（`KEY_VERSION_GRACE_EXPIRED`），
    **绝不**静默拿新版本或其它版本降级解密；
  - 当前版本始终可解；密文标注的版本从未存在 → `KEY_VERSION_UNKNOWN`；
    GCM 认证失败 / 信封解析失败 → `BAD_CIPHERTEXT`。
- **并发轮换**：密钥全部可变状态收敛为一个不可变状态对象，轮换通过 **CAS 原子发布**。
  对同一版本竞争的一批请求**恰好一个成功**；其余返回可区分的
  `RotationOutcome.Conflict(currentVersion)`（HTTP `409`，`rotated=false`），
  它们离线生成的密钥材料直接丢弃，**不发布任何中间状态**，版本只前进一格。每次冲突也留审计。

## 2. 租约与作用域规则

- 主体必须先通过 `POST /api/subjects` **注册**；向未注册主体签发 → `UNKNOWN_SUBJECT`。
- 租约字段：`token`（32 字节随机，URL-safe）、`subject`、`scope`、
  `issuedAt`、`expiresAt`、`revokedAt`、签发时的 `keyVersion`。
- TTL 可按请求指定（`ttlSeconds`），缺省用 `app.default-lease-ttl`（默认 `PT5M`）。
- 读取校验**顺序固定**（保证原因可区分、可解释）：
  1. 租约不存在 → `UNKNOWN_LEASE`；
  2. 主体已不存在 → `UNKNOWN_SUBJECT`；
  3. 已撤销（`revokedAt != null`）→ `LEASE_REVOKED`（撤销判定优先于过期）；
  4. `now >= expiresAt` → `LEASE_EXPIRED`（边界即到期）；
  5. 请求作用域与租约作用域不等 → `SCOPE_MISMATCH`；
  6. 解析密文 → `BAD_CIPHERTEXT`；按版本/宽限期解密 → `KEY_VERSION_UNKNOWN` / `KEY_VERSION_GRACE_EXPIRED`；
  7. 全部通过才释放明文，返回 `ReadOutcome.Success(plaintext, keyVersionUsed)`。
- 租约记录不可变，撤销用 `ConcurrentHashMap.computeIfPresent` **原子替换**；
  并发读取只拿到不可变快照，**不同主体之间不会串用彼此的结果**（见并发隔离测试）。

## 3. 审计策略（fail-closed）

- **签发 ISSUE、读取 READ、轮换 ROTATE、撤销 REVOKE** 全部留痕，每条事件包含：
  时间、动作、主体（轮换为 `system`）、作用域、密钥版本（无法确定时为 -1）、
  结果（`ALLOW` / `DENY_*`）与判定细节。
- 成功/拒绝都要先写审计再交付：
  - **读取**：成功审计写失败 → 抛 `AUDIT_FAILURE`（HTTP 503），**明文绝不释放**；
    拒绝审计写失败 → 升级为 `AUDIT_FAILURE`，绝不静默放行。
  - **签发**：先写审计再使租约可见，审计失败则租约不留存。
  - **撤销**是降低权限操作：状态先生效再写审计；即使审计失败，撤销依然有效。
  - 撤销之后的读取会被拒绝，且该拒绝同样进入审计。

### 错误原因 → HTTP 状态码

| Reason | HTTP |
|---|---|
| `UNKNOWN_SUBJECT` / `SCOPE_MISMATCH` / `LEASE_EXPIRED` / `LEASE_REVOKED` | 403 |
| `UNKNOWN_LEASE` / `KEY_VERSION_UNKNOWN` | 404 |
| `KEY_VERSION_GRACE_EXPIRED` | 409 |
| `ROTATION_CONFLICT`（rotate 返回体 `rotated=false`） | 409 |
| `BAD_CIPHERTEXT` | 400 |
| `AUDIT_FAILURE` | 503 |

错误体统一为 `{"error":"<REASON>","message":"<判定依据>"}`。

## 4. HTTP API

| 方法 路径 | 说明 |
|---|---|
| `POST /api/subjects` | `{subject}` 注册主体 |
| `POST /api/seal` | `{plaintext}` 用当前版本加密，返回 `{ciphertext,keyVersion}` |
| `POST /api/leases` | `{subject,scope,ttlSeconds?}` 签发租约（201） |
| `POST /api/read` | `{leaseToken,scope,ciphertext}` 返回 `{plaintext,keyVersionUsed}` |
| `POST /api/rotate` | 轮换：成功 200 `{rotated:true,version:n}`；冲突 409 `{rotated:false,version:当前}` |
| `POST /api/revoke` | `{leaseToken}` 撤销 |

手工验证：

```bash
mvn spring-boot:run
curl -s -XPOST localhost:8080/api/subjects -H 'Content-Type: application/json' -d '{"subject":"alice"}'
curl -s -XPOST localhost:8080/api/seal -H 'Content-Type: application/json' -d '{"plaintext":"salary"}'
curl -s -XPOST localhost:8080/api/leases -H 'Content-Type: application/json' \
  -d '{"subject":"alice","scope":"payroll","ttlSeconds":300}'
curl -s -XPOST localhost:8080/api/read -H 'Content-Type: application/json' \
  -d '{"leaseToken":"<token>","scope":"payroll","ciphertext":"<密文>"}'
curl -s -XPOST localhost:8080/api/rotate
curl -s -XPOST localhost:8080/api/revoke -H 'Content-Type: application/json' -d '{"leaseToken":"<token>"}'
```

## 5. 测试与验证方法

```bash
mvn test
```

覆盖（19 个用例，单测日志以 `SCENARIO` logger 打印**输入条件**与**判定依据/结果**）：

- `KeyManagerTests`：宽限期边界（差 1ns 可解、到点精确拒绝）、旧版本不静默降级、
  未知版本、密文被篡改、非法信封。
- `RotationConcurrencyTests`：16 线程屏障同步争抢同一版本，**恰一成功**、其余冲突、
  版本只前进一格、冲突全部留痕；轮换前后旧/新密文明文一致且版本号可区分，宽限期后旧拒新可读。
- `LeaseAccessTests`：正常读取、未注册主体、未知租约、已撤销、已过期（边界）、
  作用域越权、撤销不存在租约，以及对应审计字段。
- `AuditPolicyTests`：审计存储故障时读取/签发 fail-closed、四类动作的审计字段完整性、
  撤销后读取的拒绝留痕。
- `ConcurrentReadIsolationTests`：24 主体 × 20 轮并发，合法读取全部拿到自己的明文，
  跨主体尝试全部 `SCOPE_MISMATCH`，零串用。
- `WebApiIntegrationTests`：经 HTTP 端到端走通注册/加密/签发/读取/轮换/宽限/撤销，
  并校验各原因码到状态码的映射。

## 6. 主要代码结构

```
clock/    TimeSource（生产 SystemTimeSource，测试 MutableTimeSource 可控时钟）
crypto/   LocalKeyManager（版本+CAS轮换+宽限期）、ManagedCiphertext、CiphertextCodec
lease/    Lease（不可变记录）、LeaseStore（并发安全主体/租约存储）
audit/    AuditEvent/Action/Result、AuditSink、InMemoryAuditSink（可注入故障）
service/  SecretService 统一门面 + DefaultSecretService 编排（校验→解密→审计）
web/      SecretController、ApiExceptionHandler、ApiDtos
config/   AppProperties（grace-period / default-lease-ttl）、ServiceConfig
```
