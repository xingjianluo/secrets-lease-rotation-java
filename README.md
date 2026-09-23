# 本地密钥托管与租约访问（Secrets Lease & Rotation）

用**本地密钥材料**模拟受管密钥（managed key），在一个 Spring Boot 进程内实现：

- 密钥版本的引入与**轮换**，旧版本密文在**宽限期**内仍可解、过期后被明确拒绝；
- 按**主体（subject）+ 作用域（scope）**签发短期**租约（lease）**，读取时强校验；
- 签发 / 读取 / 轮换 / 撤销的**完整审计**，审计失败时敏感操作 **fail-closed**；
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
| 版本号在库中不存在 | — | 拒绝 `UNKNOWN_KEY_VERSION`（密文损坏同样归此原因） |

> 边界约定：`now == graceDeadline` 即视为宽限**结束**（左闭右开区间）。

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

## 3. 审计

每个动作（`ISSUE_LEASE` / `READ_SECRET` / `ROTATE` / `REVOKE_LEASE` / `ENCRYPT_SECRET`）
都落一条审计记录，字段包含：时间、动作、主体、作用域、密钥版本、租约 ID、
结果（`SUCCESS` 或 `DENIED:<原因>`）、判定依据明细。

- **成功与被拒绝都留痕**，包括撤销之后的读取（体现为 `DENIED:LEASE_REVOKED`）。
- **fail-closed**：读取在返回明文前先写审计；审计写入失败则抛 `AUDIT_FAILURE`
  （HTTP 503），绝不静默放行，也不会留下"成功读取"记录。

### 错误原因归类（跨入口一致）

| `DenyReason` | 含义 | HTTP |
|---|---|---|
| `ROTATION_IN_PROGRESS` | 并发轮换冲突 | 409 |
| `UNKNOWN_KEY_VERSION` | 版本不存在 / 密文损坏 | 410 |
| `KEY_VERSION_GRACE_EXPIRED` | 旧版本宽限期结束 | 410 |
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
| `POST /api/leases/revoke` | `{"leaseId":"..."}` | 撤销租约 |

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
- `SecretLeaseApiTests`：同一判定经 REST 得到固定状态码与同一 `reason`。

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
```

## 6. 代码结构

```
model/      KeyVersion(不可变版本快照) Lease AuditEvent 各结果记录 DenyReason/Action
crypto/     LocalCryptoService(AES-256-GCM) 与密文信封解析
service/    ManagedKeyStore(原子快照+轮换锁) LeaseStore SecretLeaseService(门面)
audit/      AuditSink 接口与可注入故障的内存实现
api/        REST 控制器与统一异常映射
config/     Clock Bean（测试可替换为可控时钟）
```
