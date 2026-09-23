package com.github.xingjianluo.secretsleaserotationjava.lease;

import java.time.Instant;

/**
 * 短期访问租约。
 *
 * @param token     租约标识（不可猜测）
 * @param subject   承租主体
 * @param scope     允许访问的作用域
 * @param issuedAt  签发时刻
 * @param expiresAt 到期时刻
 * @param revokedAt 撤销时刻；{@code null} 表示未撤销
 * @param keyVersion 签发时对应的密钥版本
 */
public record Lease(String token,
                    String subject,
                    String scope,
                    Instant issuedAt,
                    Instant expiresAt,
                    Instant revokedAt,
                    int keyVersion) {

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /** 返回一份被撤销的副本。 */
    public Lease revoked(Instant at) {
        return new Lease(token, subject, scope, issuedAt, expiresAt, at, keyVersion);
    }
}
