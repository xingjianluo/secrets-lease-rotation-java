# 本地密钥托管与租约访问（Secrets Lease & Rotation）

用**本地密钥材料**模拟受管密钥（managed key），在一个 Spring Boot 进程内实现：

- 密钥版本的引入与**轮换**，旧版本密文在**宽限期**内仍可解、过期后被明确拒绝；
- 按**主体（subject）+ 作用域（scope）**签发短期**租约（lease）**，读取时强校验；
- **密文升级（re-encrypt upgrade）**：持有效租约可把仍可读的旧版本密文重新加密为当前版本，
  支持整批并行升级（全有或全无），与轮换并发时结论可解释；
- **退役版本清理（purge）**：宽限期结束的退役版本可移出托管库；清理后再读/再升级被明确识别为
  “版本已移除”，绝不拿当前版本顶替；
- 签发 / 读取 / 轮换 / 撤销 / 升级 / 清理的**完整审计**，审计失败时敏感操作 **fail-closed**；
- 同一判定无论是走服务门面还是走 REST，都得到**一致且可解释**的结论。

密钥与密文都只存在于内存 / 调用方，不依赖任何外部 KMS。

---

## 1. 密钥版本与宽限策略

- 系统启动时创建初始版本 `v1`（256 位随机 AES 密钥）。
- 每次轮换产生 `v(n+1)`：旧 `current` 变为 **retired** 并记录
  `retiredAt` 与 `graceDeadline = rotatedAt + gracePeriod`，新版本成为 `current`。
- 加密始终用 `current`；密文自带**版本前缀**，因此读取时先用密文里的版本号定位密钥，
  绝不会"猜一个密钥试试"。

| 密文所用版本 | 状态 | 读取结论 |
|---|---|---|
| `current` | 当前版本 | 正常解密 |
| `retired` 且 `now < graceDeadline` | 宽限期内 | 正常解密（旧密文平滑过渡） |
| `retired` 且 `now >= graceDeadline` | 宽限期结束 | **明确拒绝 `KEY_VERSION_GRACE_EXPIRED`**，不回退、不静默降级 |
| `purged`（墓碑） | 已被清理移出 | **明确拒绝 `KEY_VERSION_PURGED`**（与“从未存在”区分，不拿 current 顶替） |
| 版本号在库中不存在 | — | 拒绝 `UNKNOWN_KEY_VERSION`（信封格式损坏同样归此原因） |

> 边界约定：`now == graceDeadline` 即视为宽限**结束**（左闭右开区间）；
> 因此清理也只在 `now >= graceDeadline` 时被允许。

### 版本状态机与兼容范围

```
CURRENT ──rotate()──▶ RETIRED(retiredAt, graceDeadline) ──purge()──▶ PURGED(墓碑, purgedAt)
   │                      │ 可读/可升级：now < graceDeadline           │ 读/升级：KEY_VERSION_PURGED
   │                      │ 读/升级：now >= deadline → GRACE_EXPIRED   │ 密钥材料已销毁
   └─可加密/可解密         └─ 不能再清理回到 current                    └─ 不可恢复
```

- `purge` 前置条件（任一不满足都明确拒绝并留痕）：
  版本存在 → 不是 `current`（`KEY_VERSION_NOT_PURGEABLE`）→
  宽限期已结束（`KEY_VERSION_NOT_PURGEABLE`）→ 尚未被清理
  （重复清理为 `KEY_VERSION_PURGED`）。
- 清理以**墓碑**替换版本：密钥材料立即不可用，但保留版本号、退役/宽限/清理时刻，
  因此后续读取能给出“这个版本已经被移除了”而不是含糊的“不存在”。
- 版本号只增不复用，墓碑也永不复活。

### 并发轮换的正确性

- 整个版本集合是一个**不可变快照**，通过 `AtomicReference` **一次性原子发布**：
  任何并发读取看到的要么是轮换前、要么是轮换后的完整状态，**不存在中间状态**。
- 轮换用 `ReentrantLock.tryLock()`：同一时刻只有一个轮换能进入关键区，
  其余**立即**以可区分的 `ROTATION_IN_PROGRESS`（HTTP 409）拒绝，且不改动任何状态。

密文线路格式：

```
v<版本号>:<作用域>:<Base64( iv(12B) || AES-256-GCM(ciphertext||tag) )>
```

---

## 1.5 密文升级（upgrade）与并发正确性

持一张**有效租约**，可以把一份（或一批）现在仍可读的密文重新加密到当前版本：

- 升级前后解出的**明文与作用域完全一致**；升级后的密文用**同一张租约**再读，
  `keyVersion` 落在升级时的当前版本上；
- 判定顺序与读取一致：信封可解析 → 租约存在/主体登记/作用域匹配/未撤销/未过期 →
  源版本存在 → 未被清理 → 在宽限期内 → **GCM 完整性通过（防篡改）**；
- **全有或全无**：批量请求中任意一份被拒绝（例如其中一份被篡改），整批拒绝，
  且响应中**绝不包含任何新密文**；
- 批量重加密在版本变更锁内**并行执行**（`CompletableFuture` 公共池），量大时不串行退化，
  返回顺序仍与入参一致；
- 密文被篡改（GCM tag 对不上）归类为 `CIPHERTEXT_INVALID`（HTTP 422），
  与“版本不存在 / 信封格式损坏”（`UNKNOWN_KEY_VERSION`）区分。

### 升级与轮换/清理并发时的结论

版本变更（轮换、清理）与升级共用同一把锁，且版本集合始终是**原子发布的不可变快照**：

- 每次升级要么完整落到**当时真实存在的当前版本**，要么以
  `ROTATION_IN_PROGRESS`（HTTP 409，可重试）被**明确拒绝**——
  不会产出引用不存在版本的密文，读侧也看不到“升级到一半”的状态；
- 同一份密文被并发升级多次：每次结论都是独立的“1 份输入 → 1 份新密文”，
  内容与计数不会互相串扰；冲突方拿 409 而不是半成品；
- 清理在同一把锁内、且**审计先于状态发布**：审计写不进去，快照保持原样，
  不会出现“版本已被清掉但查无记录”。

---

## 2. 租约与作用域规则

- 主体必须先登记（`POST /api/subjects`），未登记主体不能获得租约。
- 租约绑定三元组 `subject + scope + 有效期`，返回 `leaseId`。
- 读取时必须出示 `leaseId` 与密文，按**固定顺序**判定（结果可解释）：

1. 密文可解析（否则 `UNKNOWN_KEY_VERSION`）
2. 租约存在（否则 `UNKNOWN_LEASE`）
3. 租约主体仍在登记表中（否则 `UNKNOWN_SUBJECT`）
4. **租约作用域 == 密文作用域**（否则 `SCOPE_MISMATCH`，即越权）
5. 租约未被撤销（否则 `LEASE_REVOKED`）
6. 租约未过期：`now < expiresAt`，`now == expiresAt` 即过期（否则 `LEASE_EXPIRED`）
7. 密钥版本存在（否则 `UNKNOWN_KEY_VERSION`）
8. 版本未被清理（否则 `KEY_VERSION_PURGED`）
9. 旧版本仍在宽限期（否则 `KEY_VERSION_GRACE_EXPIRED`）
10. AES-GCM 解密通过（密钥不符/被篡改 → `CIPHERTEXT_INVALID`）
11. **审计成功**后才返回明文

- 撤销幂等；撤销发生在过期判断之前，因此"既撤销又过期"会归类为 `LEASE_REVOKED`。
- 读取路径**不做跨请求 / 跨主体的结果缓存**，每次都按租约独立判定；
  并发读取不会串用不同主体的结果（有 400 次并发读取的隔离测试保障）。

---

## 3. 审计

每个动作（`ISSUE_LEASE` / `READ_SECRET` / `ROTATE` / `REVOKE_LEASE` / `ENCRYPT_SECRET`
/ `UPGRADE_CIPHERTEXT` / `PURGE_KEY_VERSION`）都落一条审计记录，字段包含：时间、动作、
主体、作用域、密钥版本、租约 ID、结果（`SUCCESS` 或 `DENIED:<原因>`）、判定依据明细。

- **成功与被拒绝都留痕**，包括撤销之后的读取、被篡改密文的升级、对未到期版本的清理请求。
- **fail-closed**：读取/升级在返回敏感结果前先写审计；清理在状态发布前先写审计。
  审计写入失败则抛 `AUDIT_FAILURE`（HTTP 503），绝不静默放行，也不留“状态变了无记录”。

### 错误原因归类（跨入口一致）

| `DenyReason` | 含义 | HTTP |
|---|---|---|
| `ROTATION_IN_PROGRESS` | 轮换/清理/升级并发冲突，可重试 | 409 |
| `UNKNOWN_KEY_VERSION` | 版本不存在 / 信封格式损坏 | 410 |
| `KEY_VERSION_GRACE_EXPIRED` | 旧版本宽限期结束（读/升级） | 410 |
| `KEY_VERSION_PURGED` | 版本曾存在但已被清理移出 | 410 |
| `KEY_VERSION_NOT_PURGEABLE` | 当前版本或宽限未到，不允许清理 | 409 |
| `CIPHERTEXT_INVALID` | GCM 完整性失败，密文被篡改 | 422 |
| `UNKNOWN_SUBJECT` | 主体未登记 | 404 |
| `UNKNOWN_LEASE` | 租约不存在 | 404 |
| `LEASE_EXPIRED` | 租约已过期 | 403 |
| `LEASE_REVOKED` | 租约已撤销 | 403 |
| `SCOPE_MISMATCH` | 作用域不匹配（越权） | 403 |
| `AUDIT_FAILURE` | 审计写入失败，fail-closed | 503 |

---

## 4. HTTP 接口

| 方法 & 路径 | 请求体 | 说明 |
|---|---|---|
| `POST /api/subjects` | `{"subject":"alice"}` | 登记主体（201） |
| `POST /api/encrypt` | `{"scope":"payroll","plaintext":"..."}` | 用当前版本加密 |
| `POST /api/keys/rotate` | `{"gracePeriod":"PT24H"}`（可省略，默认 24h） | 轮换密钥版本 |
| `POST /api/leases` | `{"subject":"alice","scope":"payroll","ttl":"PT5M"}` | 签发租约（201） |
| `POST /api/read` | `{"leaseId":"...","ciphertext":"v1:payroll:..."}` | 凭租约读取明文 |
| `POST /api/secrets/upgrade` | `{"leaseId":"...","ciphertext":"v1:payroll:..."}` | 单份旧密文升级到当前版本 |
| `POST /api/secrets/upgrade-batch` | `{"leaseId":"...","ciphertexts":["v1:payroll:...", ...]}` | 一批密文并行升级（全有或全无） |
| `POST /api/keys/purge` | `{"version":1}` | 清理宽限期已结束的退役版本 |
| `POST /api/leases/revoke` | `{"leaseId":"..."}` | 撤销租约 |

升级成功响应示例（批量为 `items` 数组，字段与单份一致）：

```json
{
  "leaseId": "...", "subject": "alice", "scope": "payroll",
  "targetVersion": 2,
  "items": [
    {"scope":"payroll","sourceVersion":1,"targetVersion":2,
     "sourceCiphertext":"v1:payroll:...","ciphertext":"v2:payroll:..."}
  ]
}
```

清理成功响应：`{"version":1,"purgedAt":"...","graceDeadline":"..."}`。

错误响应统一为 `{"at":...,"reason":"<DenyReason>","message":"...判定依据..."}`。

---

## 5. 验证方法

```bash
# 运行全部单元 / 并发 / 审计 / REST 测试
mvn test
```

测试用**可控时钟**（`TestInfra`）精确推进时间，不依赖真实 `sleep`，
并在日志中打印**输入与判定依据**。覆盖：

- `SecretLeaseFlowTests`：轮换前后可解性一致；宽限期内 / 截止前一刻 /
  截止时刻边界；作用域越权、过期、撤销、未知主体 / 租约；未知版本与损坏密文。
- `ConcurrentRotationTests`：确定性单重冲突（恰好一个成功、另一个 409，
  关键区中版本保持不变）；32 并发轮换压力（成功版本 2..N 连续、无重复无跳号）。
- `ConcurrentReadIsolationTests`：8 主体 × 50 轮共 400 次并发读取不串结果；
  200 次跨作用域越权全部 `SCOPE_MISMATCH`。
- `AuditTests`：四类动作均留痕且关联主体 / 作用域 / 版本 / 结果；
  审计注入失败时读取 fail-closed 且无明文泄露；撤销后的读取也进审计。
- `SecretLeaseApiTests`：同一判定经 REST 得到固定状态码与同一 `reason`；
  新增升级（宽限 0 → 410 `KEY_VERSION_GRACE_EXPIRED`）、清理（成功 / 清理当前版本 409 /
  重复清理与清理后读取 410 `KEY_VERSION_PURGED`）、未知租约升级 404 的 HTTP 一致性。
- `UpgradePurgeTests`：宽限期内升级到当前版本且再读落在新版本；32 份批量并行升级
  明文逐一一致、顺序与入参一致、混入篡改密文时整批拒绝（`CIPHERTEXT_INVALID`）无新密文；
  宽限临界点（前一刻成功 / 截止时刻拒绝）；篡改密文升级拒绝且审计只见 `DENIED`；
  未知租约 / 越权 / 过期租约升级拒绝；清理前置条件（当前版本、宽限未到、未知版本）、
  清理成功留痕、重复清理 `KEY_VERSION_PURGED`、清理后读与升级均 410 且当前版本不受影响。
- `ConcurrentUpgradeRotationTests`：4 升级线程与 4 轮换线程同时起跑，
  每份成功产出都引用真实存在的当前版本、可立即读出且明文一致，冲突方得可解释的 409；
  同一份密文 12 线程并发升级，成功结论计数恒为 1、内容不串扰。
- `UpgradePurgeAuditTests`：升级成功/拒绝均留痕且字段关联正确；
  审计失败时升级 fail-closed 不返回新密文、原密文仍按旧版本读取；
  审计失败时清理中止（版本不变成墓碑），恢复后清理成功并可追溯。

### 手工冒烟（启动后）

```bash
mvn spring-boot:run
curl -s -XPOST localhost:8080/api/subjects -H'Content-Type: application/json' \
  -d '{"subject":"alice"}'
curl -s -XPOST localhost:8080/api/encrypt -H'Content-Type: application/json' \
  -d '{"scope":"payroll","plaintext":"salary-4242"}'
curl -s -XPOST localhost:8080/api/leases -H'Content-Type: application/json' \
  -d '{"subject":"alice","scope":"payroll","ttl":"PT5M"}'
# 用上两步返回的 ciphertext / leaseId 读取：
curl -s -XPOST localhost:8080/api/read -H'Content-Type: application/json' \
  -d '{"leaseId":"...","ciphertext":"..."}'
# 轮换（给一段宽限期，便于观察升级）：
curl -s -XPOST localhost:8080/api/keys/rotate -H'Content-Type: application/json' \
  -d '{"gracePeriod":"PT24H"}'
# 把旧 v1 密文升级为当前 v2 密文（批量接口把 ciphertext 换成 ciphertexts 数组即可）：
curl -s -XPOST localhost:8080/api/secrets/upgrade -H'Content-Type: application/json' \
  -d '{"leaseId":"...","ciphertext":"v1:payroll:..."}'
# 宽限期结束后清理 v1；清理后再拿 v1 密文去读/升级会得到 410 KEY_VERSION_PURGED：
curl -s -XPOST localhost:8080/api/keys/purge -H'Content-Type: application/json' \
  -d '{"version":1}'
```

## 6. 代码结构

```
model/      KeyVersion(current/retired/purged 不可变快照) Lease AuditEvent
            UpgradeResult/UpgradeItemResult/PurgeResult 各结果记录 DenyReason/Action
crypto/     LocalCryptoService(AES-256-GCM；解析失败=UNKNOWN_KEY_VERSION，GCM失败=CIPHERTEXT_INVALID)
service/    ManagedKeyStore(原子快照+版本变更锁: 轮换/升级/清理互斥；清理留墓碑)
            LeaseStore SecretLeaseService(门面: 读取/升级/批量升级/清理 判定+审计)
audit/      AuditSink 接口与可注入故障的内存实现
api/        REST 控制器与统一异常映射
config/     Clock Bean（测试可替换为可控时钟）
```
