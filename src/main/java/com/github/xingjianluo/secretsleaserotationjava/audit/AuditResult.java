package com.github.xingjianluo.secretsleaserotationjava.audit;

/**
 * 审计事件对应的操作判定结果：允许（ALLOW）或拒绝原因码（DENY_*）。
 */
public enum AuditResult {
    ALLOW,
    DENY_UNKNOWN_SUBJECT,
    DENY_UNKNOWN_LEASE,
    DENY_SCOPE_MISMATCH,
    DENY_LEASE_EXPIRED,
    DENY_LEASE_REVOKED,
    DENY_KEY_VERSION_GRACE_EXPIRED,
    DENY_KEY_VERSION_UNKNOWN,
    DENY_BAD_CIPHERTEXT,
    DENY_ROTATION_CONFLICT,
    DENY_AUDIT_FAILURE
}
