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
import com.github.xingjianluo.secretsleaserotationjava.model.RevokeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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

        if (!kv.isCurrent() && !kv.isWithinGrace(now)) {
            throw denyRead(leaseId, envelope.scope(), envelope.version(),
                    new KeyGraceExpiredException("旧密钥版本 v" + kv.version()
                            + " 宽限期已结束(deadline=" + kv.graceDeadline() + "，now=" + now
                            + ")，明确拒绝，不静默降级"));
        }

        String plaintext = crypto.decrypt(kv.secret(), envelope.ivAndCiphertext());

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
