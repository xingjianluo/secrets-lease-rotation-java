package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditAction;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditSink;
import com.github.xingjianluo.secretsleaserotationjava.clock.TimeSource;
import com.github.xingjianluo.secretsleaserotationjava.config.AppProperties;
import com.github.xingjianluo.secretsleaserotationjava.crypto.CiphertextCodec;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalKeyManager;
import com.github.xingjianluo.secretsleaserotationjava.crypto.ManagedCiphertext;
import com.github.xingjianluo.secretsleaserotationjava.error.AuditWriteException;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import com.github.xingjianluo.secretsleaserotationjava.lease.Lease;
import com.github.xingjianluo.secretsleaserotationjava.lease.LeaseStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * {@link SecretService} 默认实现：租约校验、密钥版本/宽限期判定、审计全部在此统一编排，
 * 保证 HTTP 等各入口拿到的结论一致且可解释。
 *
 * <h2>fail-closed 原则</h2>
 * 所有敏感结果（签发、读取成功或拒绝、轮换、撤销）都必须先落审计再对外交付；
 * 审计抛出 {@link AuditWriteException} 时，允许类结果一律转为 AUDIT_FAILURE 拒绝，
 * 绝不静默放行。撤销等“降低权限”的状态变更即使审计失败也保持生效。
 */
@Service
public class DefaultSecretService implements SecretService {

    private final TimeSource clock;
    private final AppProperties properties;
    private final LocalKeyManager keyManager;
    private final LeaseStore leaseStore;
    private final AuditSink auditSink;
    private final SecureRandom random = new SecureRandom();

    public DefaultSecretService(TimeSource clock, AppProperties properties,
                                LocalKeyManager keyManager, LeaseStore leaseStore, AuditSink auditSink) {
        this.clock = clock;
        this.properties = properties;
        this.keyManager = keyManager;
        this.leaseStore = leaseStore;
        this.auditSink = auditSink;
    }

    @Override
    public void registerSubject(String subject) {
        leaseStore.registerSubject(subject);
    }

    @Override
    public String seal(String plaintext) {
        return CiphertextCodec.encode(keyManager.seal(plaintext));
    }

    @Override
    public int currentKeyVersion() {
        return keyManager.currentVersion();
    }

    @Override
    public LeaseView issueLease(String subject, String scope, Duration ttl) {
        Instant now = clock.now();
        // 主体不存在：先于任何状态变更直接拒绝。
        if (!leaseStore.subjectExists(subject)) {
            throw new ServiceException(Reason.UNKNOWN_SUBJECT,
                    "subject '" + subject + "' is not registered");
        }
        Duration lifetime = (ttl == null || ttl.isZero() || ttl.isNegative())
                ? properties.defaultLeaseTtl() : ttl;
        int version = keyManager.currentVersion();
        Lease lease = new Lease(newToken(), subject, scope, now, now.plus(lifetime), null, version);
        // 先落审计再使租约可见，避免出现“签发了但没有留痕”的租约。
        writeAudit(AuditAction.ISSUE, subject, scope, version, AuditResult.ALLOW,
                "lease issued, ttl=" + lifetime + ", expiresAt=" + lease.expiresAt());
        leaseStore.put(lease);
        return new LeaseView(lease.token(), subject, scope,
                lease.issuedAt(), lease.expiresAt(), version);
    }

    @Override
    public ReadOutcome read(String leaseToken, String scope, String ciphertext) {
        Instant now = clock.now();

        Optional<Lease> found = leaseStore.find(leaseToken);
        if (found.isEmpty()) {
            return deny(AuditAction.READ, null, scope, -1,
                    Reason.UNKNOWN_LEASE, "no lease exists for given token");
        }
        Lease lease = found.get();

        // 主体必须仍处于注册状态；主体注销后其租约一并失效。
        if (!leaseStore.subjectExists(lease.subject())) {
            return deny(AuditAction.READ, lease.subject(), scope, lease.keyVersion(),
                    Reason.UNKNOWN_SUBJECT, "subject '" + lease.subject() + "' is no longer registered");
        }
        // 判定顺序固定：撤销 → 过期 → 作用域，结论可解释、不串用。
        if (lease.isRevoked()) {
            return deny(AuditAction.READ, lease.subject(), scope, lease.keyVersion(),
                    Reason.LEASE_REVOKED, "lease revoked at " + lease.revokedAt());
        }
        if (lease.isExpiredAt(now)) {
            return deny(AuditAction.READ, lease.subject(), scope, lease.keyVersion(),
                    Reason.LEASE_EXPIRED, "lease expired at " + lease.expiresAt() + " (now=" + now + ")");
        }
        if (!lease.scope().equals(scope)) {
            return deny(AuditAction.READ, lease.subject(), scope, lease.keyVersion(),
                    Reason.SCOPE_MISMATCH,
                    "lease scope '" + lease.scope() + "' does not match requested scope '" + scope + "'");
        }

        // 租约有效：解析密文版本（损坏也必须留痕），再按版本/宽限期解密。
        ManagedCiphertext managed;
        try {
            managed = CiphertextCodec.decode(ciphertext);
        } catch (ServiceException e) {
            return deny(AuditAction.READ, lease.subject(), scope, -1, e.reason(), e.getMessage());
        }
        String plaintext;
        try {
            plaintext = keyManager.openDuringGrace(managed);
        } catch (ServiceException e) {
            return deny(AuditAction.READ, lease.subject(), scope, managed.keyVersion(),
                    e.reason(), e.getMessage());
        }

        writeAudit(AuditAction.READ, lease.subject(), scope, managed.keyVersion(),
                AuditResult.ALLOW, "read permitted, plaintext released");
        return new ReadOutcome.Success(plaintext, managed.keyVersion());
    }

    @Override
    public RotationOutcome rotate() {
        int before = keyManager.currentVersion();
        LocalKeyManager.RotationResult result = keyManager.tryRotate();
        if (!result.rotated()) {
            // 冲突路径：本线程的密钥材料未发布，无中间状态；版本号取赢家发布后的当前版本。
            writeAudit(AuditAction.ROTATE, "system", "rotation", result.version(),
                    AuditResult.DENY_ROTATION_CONFLICT,
                    "concurrent rotation won by v" + result.version() + "; this request rejected");
            return new RotationOutcome.Conflict(result.version());
        }
        writeAudit(AuditAction.ROTATE, "system", "rotation", result.version(),
                AuditResult.ALLOW, "key rotated from v" + before + " to v" + result.version());
        return new RotationOutcome.Rotated(result.version());
    }

    @Override
    public void revoke(String leaseToken) {
        Instant now = clock.now();
        Optional<Lease> found = leaseStore.find(leaseToken);
        if (found.isEmpty()) {
            throw new ServiceException(Reason.UNKNOWN_LEASE, "no lease exists for given token");
        }
        Lease existing = found.get();
        if (!leaseStore.subjectExists(existing.subject())) {
            throw new ServiceException(Reason.UNKNOWN_SUBJECT,
                    "subject '" + existing.subject() + "' is not registered");
        }
        boolean alreadyRevoked = existing.isRevoked();
        Lease lease = leaseStore.revoke(leaseToken, now).orElseThrow();
        String detail = alreadyRevoked
                ? "lease was already revoked at " + lease.revokedAt()
                : "lease revoked at " + lease.revokedAt();
        // 撤销是降低权限操作：状态先生效再写审计；审计失败不回滚撤销。
        writeAudit(AuditAction.REVOKE, lease.subject(), lease.scope(), lease.keyVersion(),
                AuditResult.ALLOW, detail);
    }

    // --- 内部辅助 -------------------------------------------------------

    private ReadOutcome deny(AuditAction action, String subject, String scope,
                             int keyVersion, Reason reason, String detail) {
        // 拒绝同样必须留痕；若连“拒绝”审计都写失败，则升级为 AUDIT_FAILURE，绝不放行。
        writeAudit(action, subject, scope, keyVersion, toAuditResult(reason), detail);
        return new ReadOutcome.Denied(reason, detail);
    }

    private void writeAudit(AuditAction action, String subject, String scope,
                            int keyVersion, AuditResult result, String detail) {
        try {
            auditSink.write(new AuditEvent(clock.now(), action, subject, scope,
                    keyVersion, result, detail));
        } catch (AuditWriteException e) {
            throw new ServiceException(Reason.AUDIT_FAILURE,
                    "audit storage unavailable for action " + action + "; request closed by fail-closed policy", e);
        }
    }

    private static AuditResult toAuditResult(Reason reason) {
        return switch (reason) {
            case UNKNOWN_SUBJECT -> AuditResult.DENY_UNKNOWN_SUBJECT;
            case UNKNOWN_LEASE -> AuditResult.DENY_UNKNOWN_LEASE;
            case SCOPE_MISMATCH -> AuditResult.DENY_SCOPE_MISMATCH;
            case LEASE_EXPIRED -> AuditResult.DENY_LEASE_EXPIRED;
            case LEASE_REVOKED -> AuditResult.DENY_LEASE_REVOKED;
            case KEY_VERSION_GRACE_EXPIRED -> AuditResult.DENY_KEY_VERSION_GRACE_EXPIRED;
            case KEY_VERSION_UNKNOWN -> AuditResult.DENY_KEY_VERSION_UNKNOWN;
            case BAD_CIPHERTEXT -> AuditResult.DENY_BAD_CIPHERTEXT;
            case ROTATION_CONFLICT -> AuditResult.DENY_ROTATION_CONFLICT;
            case AUDIT_FAILURE -> AuditResult.DENY_AUDIT_FAILURE;
        };
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
