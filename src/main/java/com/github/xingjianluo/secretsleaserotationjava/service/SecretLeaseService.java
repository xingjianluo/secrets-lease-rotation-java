package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditSink;
import com.github.xingjianluo.secretsleaserotationjava.crypto.Envelope;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseRevokedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.RotationConflictException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownSubjectException;
import com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException;
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
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeItemResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

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

        KeyVersion kv = keyStore.findVersion(envelope.version())
                .orElseThrow(() -> denyRead(leaseId, envelope.scope(), envelope.version(),
                        new com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException(
                                "密文引用的密钥版本不存在: v" + envelope.version())));

        if (kv.isPurged()) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException(
                            "密钥版本 v" + kv.version() + " 已被清理移出托管库（清理于 "
                                    + kv.purgedAt() + "），明确拒绝，不回退到当前版本"));
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
        } catch (com.github.xingjianluo.secretsleaserotationjava.exception.CiphertextInvalidException e) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(), e);
        }

        // 审计先于明文返回：审计落不下来就拒绝，敏感读取绝不被静默放行
        audit(Action.READ_SECRET, lease.subject(), envelope.scope(), kv.version(),
                leaseId, "SUCCESS", "校验全部通过，使用 v" + kv.version() + " 解密");
        log.info("读取成功: leaseId={}, subject={}, scope={}, keyVersion=v{}, 依据=租约有效+作用域匹配+版本在宽限内",
                leaseId, lease.subject(), envelope.scope(), kv.version());
        return new SecretReadResult(leaseId, lease.subject(), envelope.scope(),
                kv.version(), plaintext);
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

    /** 把一份旧版本密文升级为当前版本密文（单份，等价于只提交一项的批量）。 */
    public UpgradeResult upgrade(String leaseId, String ciphertext) {
        return upgradeBatch(leaseId, java.util.List.of(ciphertext));
    }

    /**
     * 批量升级：持有效租约，把一批现在还能读的旧版本密文重新加密为当前版本。
     *
     * <p>不变量：
     * <ul>
     *   <li>升级前后明文与作用域完全一致；升级后的密文凭同一租约再读落在当前版本；</li>
     *   <li>密文不可解（篡改）、租约关不过、版本被清理/超宽限——整批拒绝，
     *       绝不吐出任何新密文（全有或全无）；</li>
     *   <li>与轮换/清理互斥：在版本变更锁内一次性完成，每份产出引用的必是当时真实存在的
     *       当前版本；重加密量大时在锁内并行执行，不退化串行；</li>
     *   <li>审计先于结果返回，审计失败 fail-closed。</li>
     * </ul>
     */
    public UpgradeResult upgradeBatch(String leaseId, java.util.List<String> ciphertexts) {
        if (ciphertexts == null || ciphertexts.isEmpty()) {
            throw new IllegalArgumentException("ciphertexts 不能为空");
        }
        final List<Envelope> envelopes = new java.util.ArrayList<>(ciphertexts.size());
        for (String ct : ciphertexts) {
            try {
                envelopes.add(crypto.parse(ct));
            } catch (SecretLeaseException e) {
                denyUpgrade(leaseId, null, null, e, 0, ciphertexts.size());
                throw e;
            }
        }

        // 租约关：所有密文必须与同一张租约的作用域一致（整批共用一个作用域）
        Lease lease = leaseStore.find(leaseId)
                .orElseThrow(() -> denyUpgrade(leaseId, envelopes.get(0).scope(),
                        envelopes.get(0).version(),
                        new UnknownLeaseException("租约不存在: " + leaseId),
                        0, ciphertexts.size()));
        Instant now = Instant.now(clock);
        SecretLeaseException leaseError = validateLease(lease, envelopes.get(0), now);
        if (leaseError != null) {
            throw denyUpgrade(leaseId, envelopes.get(0).scope(), envelopes.get(0).version(),
                    leaseError, 0, ciphertexts.size());
        }
        for (int i = 1; i < envelopes.size(); i++) {
            Envelope env = envelopes.get(i);
            if (!env.scope().equals(lease.scope())) {
                ScopeMismatchException e = new ScopeMismatchException("作用域不匹配: 租约作用域='"
                        + lease.scope() + "'，密文作用域='" + env.scope() + "'");
                throw denyUpgrade(leaseId, env.scope(), env.version(), e, i, ciphertexts.size());
            }
        }

        try {
            // 锁内完成 版本定位→解密→重加密→审计，期间不会穿插轮换/清理
            return keyStore.withMutationLock(() -> doUpgrade(lease, envelopes, ciphertexts));
        } catch (RotationConflictException e) {
            denyUpgrade(leaseId, lease.scope(), keyStore.current().version(), e,
                    0, ciphertexts.size());
            throw e;
        }
    }

    /** 锁内执行批量升级：源版本必须真实存在且仍可解，随后并行重加密到当前版本。 */
    private UpgradeResult doUpgrade(Lease lease, List<Envelope> envelopes,
                                    List<String> rawCiphertexts) {
        final KeyVersion target = keyStore.current();
        final Instant now = Instant.now(clock);
        // 先做全部源版本定位与可解性判定，任一项不过即整批拒绝（此阶段不产出任何新密文）
        final List<String> plaintexts = new java.util.ArrayList<>(envelopes.size());
        for (int i = 0; i < envelopes.size(); i++) {
            Envelope env = envelopes.get(i);
            final int itemIndex = i;
            KeyVersion source = keyStore.findVersion(env.version())
                    .orElseThrow(() -> denyUpgrade(lease.leaseId(), env.scope(), env.version(),
                            new com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException(
                                    "密文引用的密钥版本不存在: v" + env.version()),
                            itemIndex, envelopes.size()));
            if (source.isPurged()) {
                throw denyUpgrade(lease.leaseId(), env.scope(), env.version(),
                        new com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException(
                                "密钥版本 v" + source.version() + " 已被清理移出，拒绝升级"),
                        itemIndex, envelopes.size());
            }
            if (!source.isCurrent() && !source.isWithinGrace(now)) {
                throw denyUpgrade(lease.leaseId(), env.scope(), env.version(),
                        new KeyGraceExpiredException("旧密钥版本 v" + source.version()
                                + " 宽限期已结束(deadline=" + source.graceDeadline()
                                + "，now=" + now + ")，拒绝升级"),
                        itemIndex, envelopes.size());
            }
            // GCM 校验：被篡改的密文在这里被明确识别，绝不为其生成新密文
            try {
                plaintexts.add(crypto.decrypt(source.secret(), env.ivAndCiphertext()));
            } catch (com.github.xingjianluo.secretsleaserotationjava.exception.CiphertextInvalidException e) {
                throw denyUpgrade(lease.leaseId(), env.scope(), env.version(), e,
                        itemIndex, envelopes.size());
            }
        }

        // 全部可解后并行重加密到同一个当前版本（量大时不串行退化），再按入参顺序归集
        final UpgradeItemResult[] byIndex = new UpgradeItemResult[envelopes.size()];
        if (envelopes.size() == 1) {
            String newCt = crypto.encrypt(target.version(), lease.scope(),
                    target.secret(), plaintexts.get(0));
            Envelope env = envelopes.get(0);
            byIndex[0] = new UpgradeItemResult(lease.scope(), env.version(),
                    target.version(), rawCiphertexts.get(0), newCt);
        } else {
            java.util.concurrent.CompletableFuture<?>[] futures =
                    new java.util.concurrent.CompletableFuture<?>[envelopes.size()];
            for (int i = 0; i < envelopes.size(); i++) {
                final int idx = i;
                futures[i] = java.util.concurrent.CompletableFuture.runAsync(() -> {
                    Envelope env = envelopes.get(idx);
                    String newCt = crypto.encrypt(target.version(), lease.scope(),
                            target.secret(), plaintexts.get(idx));
                    byIndex[idx] = new UpgradeItemResult(lease.scope(), env.version(),
                            target.version(), rawCiphertexts.get(idx), newCt);
                });
            }
            joinAll(futures);
        }

        // 审计先于返回：整批一条；审计写不下来则 fail-closed，不返回任何新密文
        audit(Action.UPGRADE_CIPHERTEXT, lease.subject(), lease.scope(), target.version(),
                lease.leaseId(), "SUCCESS",
                "批量升级 " + envelopes.size() + " 份 -> v" + target.version());
        log.info("升级成功: leaseId={}, subject={}, scope={}, count={}, target=v{}, 依据=租约有效+源版本可解+GCM校验通过",
                lease.leaseId(), lease.subject(), lease.scope(), envelopes.size(), target.version());
        return new UpgradeResult(lease.leaseId(), lease.subject(), lease.scope(),
                target.version(), List.of(byIndex));
    }

    private static void joinAll(java.util.concurrent.CompletableFuture<?>[] futures) {
        try {
            java.util.concurrent.CompletableFuture.allOf(futures).join();
        } catch (java.util.concurrent.CompletionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            if (cause instanceof SecretLeaseException sle) {
                throw sle;
            }
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new IllegalStateException("批量升级并行执行失败", cause);
        }
    }

    /**
     * 清理一个退役版本：仅当宽限期已结束才允许移出；当前版本、未知版本、已清理版本、
     * 宽限期未到均明确拒绝并留痕。状态变更与审计在同一版本变更锁内、且审计先行，
     * 杜绝“状态变了却查无记录”。
     */
    public PurgeResult purgeKeyVersion(Integer version) {
        if (version == null || version <= 0) {
            throw new IllegalArgumentException("version 必须为正整数");
        }
        try {
            ManagedKeyStore.PurgeOutcome out = keyStore.purge(version, () ->
                    audit(Action.PURGE_KEY_VERSION, null, null, version, null, "SUCCESS",
                            "退役版本 v" + version + " 宽限期已结束，移出托管库"));
            log.info("清理成功: version=v{}, purgedAt={}, graceDeadline={}, 依据=宽限期已结束",
                    out.version(), out.purgedAt(), out.graceDeadline());
            return new PurgeResult(out.version(), out.purgedAt(), out.graceDeadline());
        } catch (RotationConflictException e) {
            audit(Action.PURGE_KEY_VERSION, null, null, version, null,
                    "DENIED:ROTATION_IN_PROGRESS", e.getMessage());
            log.warn("清理冲突拒绝: version=v{}, 依据={}", version, e.getMessage());
            throw e;
        } catch (SecretLeaseException e) {
            audit(Action.PURGE_KEY_VERSION, null, null, version, null,
                    "DENIED:" + e.reason().name(), e.getMessage());
            log.warn("清理拒绝: version=v{}, 判定={}, 依据={}",
                    version, e.reason(), e.getMessage());
            throw e;
        }
    }

    /** 租约关校验（读取与升级共用同一固定顺序），不通过返回对应异常，通过返回 null。 */
    private SecretLeaseException validateLease(Lease lease, Envelope envelope, Instant now) {
        if (!leaseStore.isRegisteredSubject(lease.subject())) {
            return new UnknownSubjectException("租约主体未登记: " + lease.subject());
        }
        if (!lease.scope().equals(envelope.scope())) {
            return new ScopeMismatchException("作用域不匹配: 租约作用域='" + lease.scope()
                    + "'，密文作用域='" + envelope.scope() + "'");
        }
        if (lease.isRevoked()) {
            return new LeaseRevokedException("租约已撤销: " + lease.leaseId()
                    + "，撤销于 " + lease.revokedAt());
        }
        if (lease.isExpiredAt(now)) {
            return new LeaseExpiredException("租约已过期: " + lease.leaseId()
                    + "，expiresAt=" + lease.expiresAt() + "，now=" + now);
        }
        return null;
    }

    /** 记录一条被拒绝的升级审计，随后原样返回异常供上层抛出（整批拒绝，无任何新密文）。 */
    private SecretLeaseException denyUpgrade(String leaseId, String scope, Integer keyVersion,
                                             SecretLeaseException e, int index, int total) {
        audit(Action.UPGRADE_CIPHERTEXT, null, scope, keyVersion, leaseId,
                "DENIED:" + e.reason().name(),
                "批量升级整批拒绝（第" + index + "项/共" + total + "项）：" + e.getMessage());
        log.warn("升级拒绝: leaseId={}, scope={}, keyVersion={}, item={}/{}, 判定={}, 依据={}",
                leaseId, scope, keyVersion, index, total, e.reason(), e.getMessage());
        return e;
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

    /** 追加审计；审计落库异常直接上抛（fail-closed）。 */
    private void audit(Action action, String subject, String scope, Integer keyVersion,
                       String leaseId, String result, String detail) {
        auditSink.append(new AuditEvent(Instant.now(clock), action, subject, scope,
                keyVersion, leaseId, result, detail));
    }
}
