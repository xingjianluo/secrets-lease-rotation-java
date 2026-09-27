# 本地密钥托管与租约访问（Secrets Lease & Rotation）

用**本地密钥材料**模拟受管密钥（managed key），在一个 Spring Boot 进程内实现：

- 密钥版本的引入与**轮换**，旧版本密文在**宽限期**内仍可解、过期后被明确拒绝；
- 持有效租约把旧版本密文**升级（重新加密）到当前版本**，支持并行批量、全成或全拒；
- 宽限期结束后**清理退役版本**，清理后该版本读 / 升级被明确标识为"已移除"；
- 按**主体（subject）+ 作用域（scope）**签发短期**租约（lease）**，读取/升级时强校验；
- 签发 / 读取 / 升级 / 轮换 / 撤销 / 清理的**完整审计**，审计失败时敏感操作 **fail-closed**；
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
| `retired` 且 `now < graceDeadline` | 宽限期内 | 正常解密（旧密文平滑过渡，也可升级） |
| `retired` 且 `now >= graceDeadline` | 宽限期结束 | **明确拒绝 `KEY_VERSION_GRACE_EXPIRED`**，不回退、不静默降级 |
| `purged`（宽限结束后被清理） | 已移出托管库 | **明确拒绝 `KEY_VERSION_PURGED`**，不拿当前版本顶替 |
| 版本号在库中不存在（也无墓碑） | — | 拒绝 `UNKNOWN_KEY_VERSION`（密文损坏同样归此原因） |

> 边界约定：`now == graceDeadline` 即视为宽限**结束**（左闭右开区间）。

版本生命周期：`current →（轮换）→ retired（宽限期内）→（宽限结束，仍可被显式清理）→ purged`。
`purged` 只保留"墓碑"（版本号、退役/宽限/清理时刻），**密钥材料已删除**，因此系统能区分
"曾经存在但已被清理"（`KEY_VERSION_PURGED`）与"从未存在"（`UNKNOWN_KEY_VERSION`）。

### 并发变更（轮换 / 清理 / 升级）的正确性

- 整个版本集合是一个**不可变快照**，通过 `AtomicReference` **一次性原子发布**：
  任何并发读取看到的要么是变更前、要么是变更后的完整状态，**不存在中间状态**。
- 轮换与清理共用同一把 `ReentrantLock.tryLock()`：同一时刻只有一个变更能进入关键区，
  其余**立即**以可区分的 `ROTATION_IN_PROGRESS`（HTTP 409）拒绝，且不改动任何状态。
- **升级（upgrade）是只读+重加密，不修改版本库**，因此无需进入变更锁。每次批量升级在
  **请求开始时锁定一次目标当前版本**：整批条目要么全部落到这个当时真实存在的当前版本，
  要么整批被拒绝，绝不会产出引用"实际不存在版本"的密文，读取方也看不到升级到一半的状态。

密文线路格式：

```
v<版本号>:<作用域>:<Base64( iv(12B) || AES-256-GCM(ciphertext||tag) )>
```

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
8. 旧版本仍在宽限期（否则 `KEY_VERSION_GRACE_EXPIRED`）
9. AES-GCM 解密通过
10. **审计成功**后才返回明文

- 撤销幂等；撤销发生在过期判断之前，因此"既撤销又过期"会归类为 `LEASE_REVOKED`。
- 读取路径**不做跨请求 / 跨主体的结果缓存**，每次都按租约独立判定；
  并发读取不会串用不同主体的结果（有 400 次并发读取的隔离测试保障）。

---

## 2.5 密文升级（re-encrypt to current）

宽限期只是"软着陆"，真正消除老密文要靠**升级**：持有效租约者拿一份当前仍可解的旧版本密文，
请求把它重新加密为当前版本。

- 升级前后**明文、作用域完全一致**；新密文用**同一个租约**读取，落在当前版本上。
- 源密文必须通过与读取一致的判定顺序（租约有效、作用域匹配、版本存在且在宽限内、GCM 校验通过）。
  密文**被篡改 / 不可解**，或租约这关没通过（不存在 / 主体未登记 / 越权 / 撤销 / 过期），
  一律**整批明确拒绝，绝不吐出任何新密文**。
- **批量原子**：`POST /api/upgrade/batch` 一次提交多条，条目用虚拟线程**并行**处理
  （量大时不退化串行）；任一条失败则整批失败、返回体不包含任何新密文。
- 目标当前版本在**请求开始时锁定一次**，整批一致；与轮换并发时，每条新密文引用的都是
  一个当时真实存在的当前版本。升级**不删除、不修改**源密文，也不修改版本库状态。
- 已是当前版本的密文也可提交：结果为重新加密（`sourceVersion == targetVersion`），明文/作用域不变。
- 成功与拒绝都记一条 `UPGRADE_SECRET` 审计（含批次大小、失败位置、源版本→目标版本）；
  审计写失败则 fail-closed，不返回任何新密文。

## 2.6 清理退役版本（purge）

宽限期结束后，退役版本的密钥材料可以被**显式清理**出托管库，避免旧版本无限堆积。

- 只允许清理 `retired` 且 `now >= graceDeadline` 的版本；
  **当前版本不许清、宽限期未到不许清、不存在不许清、已清理不许重复清**。
  前置条件不满足返回 `KEY_VERSION_NOT_PURGEABLE`（HTTP 412），并在消息中给出判定时刻与截止时刻。
- 清理只删除密钥材料，保留**墓碑**元数据。清理之后再拿该版本密文来读或升级，
  得到的是 **`KEY_VERSION_PURGED`（HTTP 410）而不是 `UNKNOWN_KEY_VERSION`**，
  更不会用当前版本顶替解密。
- 清理动作记一条 `PURGE_KEY_VERSION` 审计，可追溯版本号、清理时刻与宽限截止时刻。
- **审计先于状态变更**：审计写不进去时关键区不发布，密钥材料不会被移除（无"状态变了无记录"）。

---

## 3. 审计

每个动作（`ISSUE_LEASE` / `READ_SECRET` / `ROTATE` / `REVOKE_LEASE` / `ENCRYPT_SECRET`
/ `UPGRADE_SECRET` / `PURGE_KEY_VERSION`）都落一条审计记录，字段包含：时间、动作、主体、作用域、
密钥版本、租约 ID、结果（`SUCCESS` 或 `DENIED:<原因>`）、判定依据明细。

- **成功与被拒绝都留痕**，包括撤销之后的读取（体现为 `DENIED:LEASE_REVOKED`）、
  被篡改密文（`DENIED:UNKNOWN_KEY_VERSION`）、宽限结束后升级（`DENIED:KEY_VERSION_GRACE_EXPIRED`）、
  清理前置条件不满足（`DENIED:KEY_VERSION_NOT_PURGEABLE`）。
- **fail-closed**：读取/升级在返回明文或新密文前先写审计；清理在移除密钥材料前先写审计。
  审计写入失败则抛 `AUDIT_FAILURE`（HTTP 503），绝不静默放行，也不会留下"状态已变但查无记录"。

### 错误原因归类（跨入口一致）

| `DenyReason` | 含义 | HTTP |
|---|---|---|
| `ROTATION_IN_PROGRESS` | 并发轮换/清理冲突 | 409 |
| `UNKNOWN_KEY_VERSION` | 版本不存在 / 密文损坏或被篡改（GCM 校验失败） | 410 |
| `KEY_VERSION_GRACE_EXPIRED` | 旧版本宽限期结束（读/升级拒绝） | 410 |
| `KEY_VERSION_PURGED` | 版本已被清理移出（读/升级拒绝，不顶替） | 410 |
| `KEY_VERSION_NOT_PURGEABLE` | 清理前置条件不满足（当前版本/宽限未到/不存在/已清理） | 412 |
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
| `POST /api/upgrade` | `{"leaseId":"...","ciphertext":"v1:payroll:..."}` | 升级单条密文到当前版本 |
| `POST /api/upgrade/batch` | `{"leaseId":"...","ciphertexts":["v1:...","v2:..."]}` | 并行批量升级（全成或全拒） |
| `POST /api/keys/purge` | `{"version":1}` | 清理一个宽限期已结束的退役版本 |
| `POST /api/leases/revoke` | `{"leaseId":"..."}` | 撤销租约 |

升级成功响应：`{"leaseId","scope","sourceVersion","targetVersion","ciphertext"}`；
批量响应：`{"count","targetVersion","items":[...]}`（顺序与输入一致）。
清理成功响应：`{"version","purgedAt","graceDeadline"}`。

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
- `UpgradeTests`：宽限期内升级（明文/作用域一致、同租约读回落当前版本）；宽限临界点
  （前一刻可升、`now==deadline` 拒绝）；已是当前版本幂等；**被篡改密文拒绝且无新密文**；
  租约无效（未知/越权/撤销）拒绝；**批量原子性**（一条坏整批拒、无部分返回、审计记失败位置）；
  读取路径篡改也被明确拒绝并留痕。
- `ConcurrentUpgradeTests`：升级与多次轮换并发——每个结果都引用真实存在的版本并能同租约读回；
  同一份密文 32 并发升级，内容不错乱、成功数与成功审计数精确相等；
  批量升级峰值并发 >1、墙钟时间短于串行下界（证明确实并行）。
- `PurgeTests`：清理前置条件（当前版本 / 宽限未到 / 不存在 / 重复清理）；
  宽限结束后清理成功、墓碑保留；**清理后读与升级均为 `KEY_VERSION_PURGED`、不被当前版本顶替**；
  审计注入失败时状态不变（fail-closed），恢复后重试成功。
- `ConcurrentRotationTests`：确定性单重冲突（恰好一个成功、另一个 409，
  关键区中版本保持不变）；32 并发轮换压力（成功版本 2..N 连续、无重复无跳号）。
- `ConcurrentReadIsolationTests`：8 主体 × 50 轮共 400 次并发读取不串结果；
  200 次跨作用域越权全部 `SCOPE_MISMATCH`。
- `AuditTests`：全部动作（含升级 / 清理）均留痕且关联主体 / 作用域 / 版本 / 结果；
  审计注入失败时读取与升级 fail-closed 且无明文 / 新密文泄露；撤销后读取、宽限后升级、
  清理前置条件不满足的拒绝也进审计。
- `SecretLeaseApiTests`：同一判定经 REST 得到固定状态码与同一 `reason`；
  覆盖升级 / 批量升级 / 清理的 200、412 与清理后读升级的 410。

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
# 轮换（宽限期设为 0 可立即观察旧密文被明确拒绝）：
curl -s -XPOST localhost:8080/api/keys/rotate -H'Content-Type: application/json' \
  -d '{"gracePeriod":"PT0S"}'

# 升级：把旧密文重新加密为当前版本（持同一租约）
curl -s -XPOST localhost:8080/api/upgrade -H'Content-Type: application/json' \
  -d '{"leaseId":"...","ciphertext":"v1:payroll:..."}'
# 批量升级（全成或全拒）：
curl -s -XPOST localhost:8080/api/upgrade/batch -H'Content-Type: application/json' \
  -d '{"leaseId":"...","ciphertexts":["v1:payroll:...","v2:payroll:..."]}'

# 清理退役版本：宽限期结束后才允许（否则 412 KEY_VERSION_NOT_PURGEABLE）
curl -s -XPOST localhost:8080/api/keys/purge -H'Content-Type: application/json' \
  -d '{"version":1}'
# 清理后再读 / 升级该版本密文：410 KEY_VERSION_PURGED
```

> 典型时序：`encrypt(v1)` → `rotate(grace=PT24H)` → 宽限期内 `upgrade` 到 v2
> →（24h 后）`purge v1` → 此后 v1 密文读/升级均 `KEY_VERSION_PURGED`。
> 宽限期设为 `PT0S` 时，轮换后需让时钟走过 deadline（真实环境即下一瞬；测试用可控时钟推进）才能清理。

## 6. 代码结构

```
model/      KeyVersion(不可变版本快照) Lease AuditEvent 各结果记录 DenyReason/Action
crypto/     LocalCryptoService(AES-256-GCM) 与密文信封解析
service/    ManagedKeyStore(原子快照+变更锁+清理墓碑) LeaseStore SecretLeaseService(门面：读/升级/清理)
audit/      AuditSink 接口与可注入故障的内存实现
api/        REST 控制器与统一异常映射
config/     Clock Bean（测试可替换为可控时钟）
```
