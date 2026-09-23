package com.github.xingjianluo.secretsleaserotationjava.error;

/**
 * 所有拒绝结果的机器可区分原因码。
 */
public enum Reason {
    /** 主体未注册（签发与读取均拒绝）。 */
    UNKNOWN_SUBJECT,
    /** 租约不存在。 */
    UNKNOWN_LEASE,
    /** 租约作用域与读取请求作用域不一致。 */
    SCOPE_MISMATCH,
    /** 租约已超过有效期。 */
    LEASE_EXPIRED,
    /** 租约已被撤销。 */
    LEASE_REVOKED,
    /** 密文使用的旧密钥版本已超出轮换宽限期。 */
    KEY_VERSION_GRACE_EXPIRED,
    /** 密文标注的密钥版本在本系统中从未存在。 */
    KEY_VERSION_UNKNOWN,
    /** 密文格式非法或无法解析。 */
    BAD_CIPHERTEXT,
    /** 并发轮换冲突：已有轮换正在进行。 */
    ROTATION_CONFLICT,
    /** 审计写入失败，按 fail-closed 拒绝敏感操作。 */
    AUDIT_FAILURE
}
