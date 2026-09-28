package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditSink;
import com.github.xingjianluo.secretsleaserotationjava.crypto.Envelope;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseRevokedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.RotationConflictException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownSubjectException;
import com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UpgradeTargetSupersededException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.KeyVersion;
import com.github.xingjianluo.secretsleaserotationjava.model.Lease;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RevokeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * 本地密钥托管与租约访问门面。所有结论在此被审计并映射为成功结果或可区分异常，
 * REST 入口与直接调用得到一致结论。
 *
 * <p>读取判定顺序（固定、可解释）：
 * 密文可解析 → 租约存在 → 主体存在 → 作用域匹配 → 未撤销 → 未过期
 * → 密钥版本存在 → 旧版本仍在宽限期 → 解密 → 审计成功（审计失败则拒绝，绝不静默放行）。
 */
@Service
public class SecretLeaseService {

    private static final Logger log = LoggerFactory.getLogger(SecretLeaseService.class);

    private final ManagedKeyStore keyStore;
    private final LeaseStore leaseStore;
    private final LocalCryptoService crypto;
    private final AuditSink auditSink;
    private final Clock clock;
    private final Duration defaultLeaseTtl;
    private final Duration defaultGracePeriod;

    public SecretLeaseService(ManagedKeyStore keyStore, LeaseStore leaseStore,
                              LocalCryptoService crypto, AuditSink auditSink, Clock clock) {
        this.keyStore = keyStore;
        this.leaseStore = leaseStore;
        this.crypto = crypto;
        this.auditSink = auditSink;
        this.clock = clock;
        this.defaultLeaseTtl = Duration.ofMinutes(5);
        this.defaultGracePeriod = Duration.ofHours(24);
    }

    /** 登记可被签发租约的主体。 */
    public void registerSubject(String subject) {
        leaseStore.registerSubject(subject);
        log.info("登记主体: subject={}", subject);
    }

    /** 用当前密钥版本加密明文，密文前缀携带版本号与作用域。 */
    public EncryptResult encrypt(String scope, String plaintext) {
        if (scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("scope 不能为空");
        }
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext 不能为空");
        }
        KeyVersion cur = keyStore.current();
        String ciphertext = crypto.encrypt(cur.version(), scope, cur.secret(), plaintext);
        audit(Action.ENCRYPT_SECRET, null, scope, cur.version(), null, "SUCCESS",
                "使用当前版本加密");
        log.info("加密成功: scope={}, keyVersion=v{}", scope, cur.version());
        return new EncryptResult(scope, cur.version(), ciphertext);
    }

    /**
     * 引入新密钥版本并轮换。旧版本进入宽限期。
     * 并发调用只有一个成功，其余抛 {@link RotationConflictException}（仍留痕），不留中间状态。
     */
    public RotateResult rotate(Duration gracePeriod) {
        Duration grace = gracePeriod != null ? gracePeriod : defaultGracePeriod;
        if (grace.isNegative()) {
            throw new IllegalArgumentException("gracePeriod 不能为负");
        }
        try {
            ManagedKeyStore.RotationOutcome out =
                    keyStore.rotate(grace, v -> crypto.generateKey());
            audit(Action.ROTATE, null, null, out.newVersion(), null, "SUCCESS",
                    "v" + out.previousVersion() + " 退役，宽限期至 "
                            + Instant.now(clock).plus(grace) + "，新版本 v" + out.newVersion());
            log.info("轮换成功: v{} -> v{}, grace={}, at={}",
                    out.previousVersion(), out.newVersion(), grace, out.rotatedAt());
            return new RotateResult(out.previousVersion(), out.newVersion(),
                    out.rotatedAt(), grace);
        } catch (RotationConflictException e) {
            audit(Action.ROTATE, null, null, keyStore.current().version(), null,
                    "DENIED:ROTATION_IN_PROGRESS", e.getMessage());
            log.warn("轮换冲突拒绝: {}", e.getMessage());
            throw e;
        }
    }

    /** 为已登记主体 + 作用域签发短期租约。 */
    public LeaseIssueResult issueLease(String subject, String scope, Duration ttl) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        if (scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("scope 不能为空");
        }
        if (!leaseStore.isRegisteredSubject(subject)) {
            UnknownSubjectException e = new UnknownSubjectException(
                    "主体未登记，拒绝签发: " + subject);
            audit(Action.ISSUE_LEASE, subject, scope, keyStore.current().version(), null,
                    "DENIED:UNKNOWN_SUBJECT", e.getMessage());
            log.warn("签发拒绝: subject={}, scope={}, 依据=主体未登记", subject, scope);
            throw e;
        }
        Duration life = ttl != null ? ttl : defaultLeaseTtl;
        if (life.isZero() || life.isNegative()) {
            throw new IllegalArgumentException("ttl 必须为正数");
        }
        Instant now = Instant.now(clock);
        Lease lease = new Lease(UUID.randomUUID().toString(), subject, scope, now, now.plus(life));
        leaseStore.put(lease);
        audit(Action.ISSUE_LEASE, subject, scope, keyStore.current().version(),
                lease.leaseId(), "SUCCESS", "有效期至 " + lease.expiresAt());
        log.info("签发租约: leaseId={}, subject={}, scope={}, expiresAt={}",
                lease.leaseId(), subject, scope, lease.expiresAt());
        return new LeaseIssueResult(lease.leaseId(), subject, scope,
                lease.issuedAt(), lease.expiresAt());
    }

    /**
     * 凭租约读取密文。任何拒绝原因都可区分且留痕；审计写失败时拒绝返回明文。
     */
    public SecretReadResult read(String leaseId, String ciphertext) {
        final Envelope envelope;
        try {
            envelope = crypto.parse(ciphertext);
        } catch (SecretLeaseException e) {
            denyRead(leaseId, null, null, e);
            throw e;
        }

        Lease lease = leaseStore.find(leaseId)
                .orElseThrow(() -> denyRead(leaseId, envelope.scope(), envelope.version(),
                        new UnknownLeaseException("租约不存在: " + leaseId)));

        if (!leaseStore.isRegisteredSubject(lease.subject())) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new UnknownSubjectException("租约主体未登记: " + lease.subject()));
        }

        if (!lease.scope().equals(envelope.scope())) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new ScopeMismatchException("作用域不匹配: 租约作用域='" + lease.scope()
                            + "'，密文作用域='" + envelope.scope() + "'"));
        }

        if (lease.isRevoked()) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new LeaseRevokedException("租约已撤销: " + leaseId
                            + "，撤销于 " + lease.revokedAt()));
        }

        Instant now = Instant.now(clock);
        if (lease.isExpiredAt(now)) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new LeaseExpiredException("租约已过期: " + leaseId
                            + "，expiresAt=" + lease.expiresAt() + "，now=" + now));
        }

        KeyVersion kv = keyStore.findVersion(envelope.version()).orElse(null);
        if (kv == null) {
            ManagedKeyStore.PurgedVersion tomb = keyStore.findPurged(envelope.version()).orElse(null);
            if (tomb != null) {
                throw denyRead(leaseId, envelope.scope(), envelope.version(),
                        new KeyVersionPurgedException("密文引用的密钥版本 v" + envelope.version()
                                + " 已被清理移出(purgedAt=" + tomb.purgedAt()
                                + ")，明确拒绝，不用当前版本顶替"));
            }
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException(
                            "密文引用的密钥版本不存在: v" + envelope.version()));
        }

        if (!kv.isCurrent() && !kv.isWithinGrace(now)) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new KeyGraceExpiredException("旧密钥版本 v" + kv.version()
                            + " 宽限期已结束(deadline=" + kv.graceDeadline() + "，now=" + now
                            + ")，明确拒绝，不静默降级"));
        }

        String plaintext;
        try {
            plaintext = crypto.decrypt(kv.secret(), envelope.ivAndCiphertext());
        } catch (SecretLeaseException e) {
            // GCM 完整性校验失败（密钥不匹配/密文被篡改）：明确拒绝并留痕，不冒泡为 500
            throw denyRead(leaseId, envelope.scope(), kv.version(),
                    new UnknownKeyVersionException(
                            "密文完整性校验或解密失败（密文可能被篡改）: v" + kv.version(), e));
        }

        // 审计先于明文返回：审计落不下来就拒绝，敏感读取绝不被静默放行
        audit(Action.READ_SECRET, lease.subject(), envelope.scope(), kv.version(),
                leaseId, "SUCCESS", "校验全部通过，使用 v" + kv.version() + " 解密");
        log.info("读取成功: leaseId={}, subject={}, scope={}, keyVersion=v{}, 依据=租约有效+作用域匹配+版本在宽限内",
                leaseId, lease.subject(), envelope.scope(), kv.version());
        return new SecretReadResult(leaseId, lease.subject(), envelope.scope(),
                kv.version(), plaintext);
    }

    /**
     * 升级单条旧版本密文到当前版本。语义见 {@link #upgradeBatch}（单条即大小为 1 的一批，全成或全败）。
     */
    public UpgradeResult upgrade(String leaseId, String ciphertext) {
        return upgradeBatch(leaseId, List.of(ciphertext)).get(0);
    }

    /**
     * 批量升级：持有效租约者把一批当前仍可解的旧版本密文，重新加密为请求开始时锁定的当前版本。
     *
     * <p>保证：
     * <ul>
     *   <li>升级前后明文、作用域完全一致；新密文用同一租约读取落在提交时仍真实存在的当前版本上；</li>
     *   <li>密文不可解（含被篡改）或租约任一项不过关，整批被明确拒绝，<b>绝不吐出任何新密文</b>；</li>
     *   <li>条目之间并行处理，量大时不退化串行；</li>
     *   <li>提交点（{@link ManagedKeyStore#commitUpgrade}）在与轮换/清理互斥的变更锁内，
     *       对最新快照复核锁定的目标版本：目标版本在处理期间被轮换取代 →
     *       {@code UPGRADE_TARGET_SUPERSEDED} 整批拒绝；已被清理 → {@code KEY_VERSION_PURGED}
     *       整批拒绝（看得出"该版本已被移除"，不用当前版本顶替，不会先返回新密文再暴露问题）；
     *       只有目标版本在提交瞬间仍是当前版本才放行——成功升级返回的密文引用的必是当前版本；</li>
     *   <li>成功与拒绝都留痕；成功审计在提交关键区内写入，审计写不进去时 fail-closed，不放行任何新密文。</li>
     * </ul>
     */
    public List<UpgradeResult> upgradeBatch(String leaseId, List<String> ciphertexts) {
        if (ciphertexts == null || ciphertexts.isEmpty()) {
            throw new IllegalArgumentException("ciphertexts 不能为空批");
        }
        final int batchSize = ciphertexts.size();
        log.info("升级请求: leaseId={}, batchSize={}", leaseId, batchSize);

        // 租约只校验一次，对整批生效；目标版本在请求开始时锁定一次，整批一致。
        // 该目标版本是否在提交时仍为当前版本，由最后的 commitUpgrade 提交点在变更锁内复核，
        // 因此处理期间发生的轮换/清理不可能让本批结果引用一个已退役/已清理的版本。
        Lease lease = leaseStore.find(leaseId).orElse(null);
        if (lease == null) {
            throw denyUpgrade(leaseId, null, 0, batchSize,
                    new UnknownLeaseException("租约不存在: " + leaseId));
        }
        if (!leaseStore.isRegisteredSubject(lease.subject())) {
            throw denyUpgrade(leaseId, lease.scope(), 0, batchSize,
                    new UnknownSubjectException("租约主体未登记: " + lease.subject()));
        }
        if (lease.isRevoked()) {
            throw denyUpgrade(leaseId, lease.scope(), 0, batchSize,
                    new LeaseRevokedException("租约已撤销: " + leaseId
                            + "，撤销于 " + lease.revokedAt()));
        }
        Instant now = Instant.now(clock);
        if (lease.isExpiredAt(now)) {
            throw denyUpgrade(leaseId, lease.scope(), 0, batchSize,
                    new LeaseExpiredException("租约已过期: " + leaseId
                            + "，expiresAt=" + lease.expiresAt() + "，now=" + now));
        }

        KeyVersion target = keyStore.current();
        final int targetVersion = target.version();

        // 先解析全部信封（纯字符串解析，顺序快速完成）：任一格式损坏则整批拒绝，
        // 此时尚未产出任何新密文
        final Envelope[] envelopes = new Envelope[batchSize];
        for (int i = 0; i < batchSize; i++) {
            final int idx = i;
            final String ct = ciphertexts.get(i);
            try {
                envelopes[i] = crypto.parse(ct);
            } catch (SecretLeaseException e) {
                log.warn("升级拒绝[{}]: leaseId={}, 输入密文头={}, 判定={}, 依据={}",
                        idx, leaseId, head(ct), e.reason(), e.getMessage());
                throw denyUpgrade(leaseId, lease.scope(), idx, batchSize, e);
            }
            if (!lease.scope().equals(envelopes[i].scope())) {
                ScopeMismatchException e = new ScopeMismatchException("作用域不匹配: 租约作用域='"
                        + lease.scope() + "'，密文[" + idx + "]作用域='"
                        + envelopes[i].scope() + "'");
                throw denyUpgrade(leaseId, lease.scope(), envelopes[i].scope(),
                        envelopes[i].version(), idx, batchSize, e);
            }
        }

        // 并行执行"旧版本校验 -> 解密 -> 用锁定目标版本重加密"
        ItemOutcome[] outcomes = new ItemOutcome[batchSize];
        boolean parallel = batchSize > 1;
        ExecutorService pool = parallel
                ? Executors.newVirtualThreadPerTaskExecutor()
                : null;
        try {
            if (parallel) {
                List<Future<?>> futures = new ArrayList<>(batchSize);
                for (int i = 0; i < batchSize; i++) {
                    final int idx = i;
                    futures.add(pool.submit(() -> {
                        try {
                            outcomes[idx] = ItemOutcome.ok(upgradeOne(lease, envelopes[idx], target));
                        } catch (SecretLeaseException e) {
                            outcomes[idx] = ItemOutcome.fail(e);
                        }
                    }));
                }
                for (Future<?> f : futures) {
                    f.get();
                }
            } else {
                try {
                    outcomes[0] = ItemOutcome.ok(upgradeOne(lease, envelopes[0], target));
                } catch (SecretLeaseException e) {
                    outcomes[0] = ItemOutcome.fail(e);
                }
            }
        } catch (ExecutionException ee) {
            throw new IllegalStateException("升级内部错误", ee.getCause());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("升级被中断", ie);
        } finally {
            if (pool != null) {
                pool.shutdown();
            }
        }

        // 任一条目失败：整批拒绝，不返回任何新密文（新密文仅存在于本方法栈，不外泄）
        for (int i = 0; i < batchSize; i++) {
            if (outcomes[i].failure() != null) {
                SecretLeaseException e = outcomes[i].failure();
                log.warn("升级拒绝[{}]: leaseId={}, scope={}, sourceVersion=v{}, 判定={}, 依据={}",
                        i, leaseId, lease.scope(), envelopes[i].version(),
                        e.reason(), e.getMessage());
                throw denyUpgrade(leaseId, lease.scope(), envelopes[i].scope(),
                        envelopes[i].version(), i, batchSize, e);
            }
        }

        List<UpgradeResult> results = new ArrayList<>(batchSize);
        for (ItemOutcome o : outcomes) {
            results.add(o.result());
        }
        final String versions = describeSourceVersions(envelopes);

        // 提交点：全部条目都已在内存中产出且无一失败。进入与轮换/清理互斥的变更锁，
        // 对最新快照复核锁定的目标版本，并在锁内写成功审计。
        //   - 目标版本已被清理 -> KEY_VERSION_PURGED（看得出"该版本已被移除"）；
        //   - 目标版本已被轮换取代 -> UPGRADE_TARGET_SUPERSEDED；
        //   - 变更仍在进行/等待超时 -> ROTATION_IN_PROGRESS；
        //   - 审计写不进去 -> AUDIT_FAILURE（fail-closed）。
        // 任一情况都整批拒绝，results 仅存在于本方法栈、不外泄。
        try {
            keyStore.commitUpgrade(targetVersion, () -> audit(
                    Action.UPGRADE_SECRET, lease.subject(), lease.scope(), targetVersion, leaseId,
                    "SUCCESS", "批次=" + batchSize + "，源版本[" + versions + "] -> v"
                            + targetVersion + "，目标版本在请求开始时锁定、提交时复核仍为当前版本"));
        } catch (KeyVersionPurgedException | UpgradeTargetSupersededException
                 | RotationConflictException e) {
            throw denyUpgradeCommit(lease, targetVersion, versions, batchSize, e);
        }
        log.info("升级成功: leaseId={}, subject={}, scope={}, batchSize={}, 源版本{} -> v{}（提交点复核通过）",
                leaseId, lease.subject(), lease.scope(), batchSize, versions, targetVersion);
        return results;
    }

    /**
     * 提交点拒绝：条目都已重加密完毕，但目标版本在处理期间被轮换/清理，或变更仍在进行。
     * 整批拒绝，不吐出任何新密文；审计的 keyVersion 记被锁定的目标版本，detail 说明这是提交点判定。
     */
    private SecretLeaseException denyUpgradeCommit(Lease lease, int targetVersion,
                                                   String sourceVersions, int batchSize,
                                                   SecretLeaseException e) {
        audit(Action.UPGRADE_SECRET, lease.subject(), lease.scope(), targetVersion, lease.leaseId(),
                "DENIED:" + e.reason().name(),
                "批次=" + batchSize + "，源版本[" + sourceVersions + "]，提交点复核目标版本 v"
                        + targetVersion + "：" + e.getMessage());
        log.warn("升级整批拒绝(提交点): leaseId={}, subject={}, scope={}, batchSize={}, 锁定目标=v{}, 判定={}, 依据={}",
                lease.leaseId(), lease.subject(), lease.scope(), batchSize,
                targetVersion, e.reason(), e.getMessage());
        return e;
    }

    /** 单条升级的纯计算：定位源版本（存活/已清理/未知）→ 宽限判定 → 解密 → 目标版本重加密。 */
    private UpgradeResult upgradeOne(Lease lease, Envelope envelope, KeyVersion target) {
        Instant now = Instant.now(clock);
        KeyVersion source = keyStore.findVersion(envelope.version()).orElse(null);
        if (source == null) {
            ManagedKeyStore.PurgedVersion tomb = keyStore.findPurged(envelope.version()).orElse(null);
            if (tomb != null) {
                throw new KeyVersionPurgedException("密文引用的密钥版本 v" + envelope.version()
                        + " 已被清理移出(purgedAt=" + tomb.purgedAt()
                        + ")，拒绝升级，不用当前版本顶替");
            }
            throw new UnknownKeyVersionException(
                    "密文引用的密钥版本不存在: v" + envelope.version());
        }
        if (!source.isCurrent() && !source.isWithinGrace(now)) {
            throw new KeyGraceExpiredException("旧密钥版本 v" + source.version()
                    + " 宽限期已结束(deadline=" + source.graceDeadline() + "，now=" + now
                    + ")，不能升级，明确拒绝");
        }
        String plaintext;
        try {
            plaintext = crypto.decrypt(source.secret(), envelope.ivAndCiphertext());
        } catch (SecretLeaseException e) {
            // 被篡改 / 密钥不匹配：完整性校验失败，拒绝且不产出新密文
            throw new UnknownKeyVersionException(
                    "密文[" + source.version() + "]完整性校验/解密失败（可能被篡改），拒绝升级", e);
        }
        String reencrypted =
                crypto.encrypt(target.version(), envelope.scope(), target.secret(), plaintext);
        return new UpgradeResult(lease.leaseId(), envelope.scope(),
                source.version(), target.version(), reencrypted);
    }

    /**
     * 清理一个退役密钥版本：只允许清理宽限期已结束的退役版本；当前版本、宽限期未到、
     * 不存在或已清理一律拒绝。清理后该版本的读/升级得到 {@code KEY_VERSION_PURGED}，
     * 不会被当前版本顶替。审计在密钥材料移除之前写入：审计失败则状态不变（fail-closed）。
     */
    public PurgeResult purgeKeyVersion(int version) {
        log.info("清理请求: keyVersion=v{}", version);
        try {
            ManagedKeyStore.PurgeOutcome out = keyStore.purge(version, o ->
                    audit(Action.PURGE_KEY_VERSION, null, null, version, null, "SUCCESS",
                            "v" + version + " 已退役且宽限期已结束(deadline=" + o.graceDeadline()
                                    + ")，于 " + o.purgedAt() + " 移出密钥材料"));
            log.info("清理成功: v{}, purgedAt={}, graceDeadline={}",
                    version, out.purgedAt(), out.graceDeadline());
            return new PurgeResult(out.version(), out.purgedAt(), out.graceDeadline());
        } catch (KeyVersionNotPurgeableException | UnknownKeyVersionException e) {
            audit(Action.PURGE_KEY_VERSION, null, null, version, null,
                    "DENIED:" + e.reason().name(), e.getMessage());
            log.warn("清理拒绝: v{}, 判定={}, 依据={}", version, e.reason(), e.getMessage());
            throw e;
        } catch (RotationConflictException e) {
            audit(Action.PURGE_KEY_VERSION, null, null, version, null,
                    "DENIED:ROTATION_IN_PROGRESS", e.getMessage());
            log.warn("清理冲突拒绝: v{}, 依据={}", version, e.getMessage());
            throw e;
        }
    }

    /** 撤销租约（幂等），并留痕。 */
    public RevokeResult revoke(String leaseId) {
        Lease lease = leaseStore.find(leaseId)
                .orElseThrow(() -> {
                    UnknownLeaseException e = new UnknownLeaseException("租约不存在，无法撤销: " + leaseId);
                    audit(Action.REVOKE_LEASE, null, null, null, leaseId,
                            "DENIED:UNKNOWN_LEASE", e.getMessage());
                    return e;
                });
        Instant now = Instant.now(clock);
        boolean already = lease.isRevoked();
        lease.revoke(now);
        audit(Action.REVOKE_LEASE, lease.subject(), lease.scope(), null, leaseId, "SUCCESS",
                already ? "租约此前已撤销（幂等）" : "租约已撤销");
        log.info("撤销租约: leaseId={}, subject={}, scope={}, alreadyRevoked={}",
                leaseId, lease.subject(), lease.scope(), already);
        return new RevokeResult(leaseId, lease.revokedAt());
    }

    public int currentKeyVersion() {
        return keyStore.current().version();
    }

    // ---- 内部辅助 ---------------------------------------------------------

    /** 记录一条被拒绝的读取审计，随后返回该异常供上层抛出。 */
    private SecretLeaseException denyRead(String leaseId, String scope, Integer keyVersion,
                                          SecretLeaseException e) {
        audit(Action.READ_SECRET, null, scope, keyVersion, leaseId,
                "DENIED:" + e.reason().name(), e.getMessage());
        log.warn("读取拒绝: leaseId={}, scope={}, keyVersion={}, 判定={}, 依据={}",
                leaseId, scope, keyVersion, e.reason(), e.getMessage());
        return e;
    }

    /** 租约级拒绝（尚无法定位密文作用域/源版本时），整批拒绝。 */
    private SecretLeaseException denyUpgrade(String leaseId, String leaseScope,
                                             int index, int batchSize, SecretLeaseException e) {
        return denyUpgrade(leaseId, leaseScope, leaseScope, null, index, batchSize, e);
    }

    /** 记录一条被拒绝的升级审计，随后返回该异常供上层抛出。整批拒绝，不吐出任何新密文。 */
    private SecretLeaseException denyUpgrade(String leaseId, String leaseScope,
                                             String cipherScope, Integer sourceVersion,
                                             int index, int batchSize,
                                             SecretLeaseException e) {
        String scope = cipherScope != null ? cipherScope : leaseScope;
        audit(Action.UPGRADE_SECRET, null, scope, sourceVersion, leaseId,
                "DENIED:" + e.reason().name(),
                "批次=" + batchSize + "，失败位置=" + index + "，依据=" + e.getMessage());
        log.warn("升级整批拒绝: leaseId={}, scope={}, sourceVersion={}, 失败位置={}/{}, 判定={}, 依据={}",
                leaseId, scope, sourceVersion, index, batchSize, e.reason(), e.getMessage());
        return e;
    }

    /** 单条升级的便捷重载（批次大小为 1，失败位置固定为 0）。 */
    private SecretLeaseException denyUpgrade(String leaseId, String leaseScope,
                                             String cipherScope, Integer sourceVersion,
                                             SecretLeaseException e) {
        return denyUpgrade(leaseId, leaseScope, cipherScope, sourceVersion, 0, 1, e);
    }

    /** 汇总一批信封的源版本，如 "v1,v1,v2"。 */
    private static String describeSourceVersions(Envelope[] envelopes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < envelopes.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('v').append(envelopes[i].version());
        }
        return sb.toString();
    }

    private static String head(String ct) {
        return ct == null ? "null" : ct.substring(0, Math.min(18, ct.length())) + "...";
    }

    /** 单个升级条目的计算结果：成功结果或失败原因二选一。 */
    private record ItemOutcome(UpgradeResult result, SecretLeaseException failure) {
        static ItemOutcome ok(UpgradeResult r) {
            return new ItemOutcome(r, null);
        }

        static ItemOutcome fail(SecretLeaseException e) {
            return new ItemOutcome(null, e);
        }
    }

    /** 追加审计；审计落库异常直接上抛（fail-closed）。 */
    private void audit(Action action, String subject, String scope, Integer keyVersion,
                       String leaseId, String result, String detail) {
        auditSink.append(new AuditEvent(Instant.now(clock), action, subject, scope,
                keyVersion, leaseId, result, detail));
    }
}
