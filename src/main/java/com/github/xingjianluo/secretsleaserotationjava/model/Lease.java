package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/**
 * 面向主体 + 作用域签发的短期租约。读取密文时必须出示且通过全部校验。
 */
public final class Lease {

    private final String leaseId;
    private final String subject;
    private final String scope;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile boolean revoked;
    private volatile Instant revokedAt;

    public Lease(String leaseId, String subject, String scope, Instant issuedAt, Instant expiresAt) {
        this.leaseId = leaseId;
        this.subject = subject;
        this.scope = scope;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String leaseId() { return leaseId; }
    public String subject() { return subject; }
    public String scope() { return scope; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public Instant revokedAt() { return revokedAt; }

    /** 撤销租约。幂等：已撤销时保留首次撤销时刻。 */
    public void revoke(Instant now) {
        if (!revoked) {
            revoked = true;
            revokedAt = now;
        }
    }

    /** 在给定时刻是否已过期。边界时刻 now == expiresAt 视为已过期。撤销状态不在此判定。 */
    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
