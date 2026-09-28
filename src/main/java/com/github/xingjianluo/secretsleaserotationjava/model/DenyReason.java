package com.github.xingjianluo.secretsleaserotationjava.model;

/**
 * 所有拒绝结论的可区分原因。任何入口（服务门面 / REST）都必须映射到本枚举之一。
 */
public enum DenyReason {
    /** 已有轮换正在进行，本次并发轮换请求冲突拒绝。 */
    ROTATION_IN_PROGRESS,
    /** 密文引用的密钥版本在本托管库中不存在。 */
    UNKNOWN_KEY_VERSION,
    /** 密钥版本已轮换且宽限期结束，旧密文被明确拒绝（不静默降级）。 */
    KEY_VERSION_GRACE_EXPIRED,
    /** 密钥版本已被清理移出托管库：再读/再升级必须明确拒绝，不得用当前版本顶替。 */
    KEY_VERSION_PURGED,
    /** 清理前置条件不满足（版本是当前版本 / 尚在宽限期 / 不存在）。 */
    KEY_VERSION_NOT_PURGEABLE,
    /** 升级在处理期间其锁定的目标版本已被轮换取代（当前版本变成了更新的版本），整批拒绝，请基于当前版本重试。 */
    UPGRADE_TARGET_SUPERSEDED,
    /** 主体不存在（未登记）。 */
    UNKNOWN_SUBJECT,
    /** 租约不存在。 */
    UNKNOWN_LEASE,
    /** 租约已超过有效期。 */
    LEASE_EXPIRED,
    /** 租约已被撤销。 */
    LEASE_REVOKED,
    /** 租约作用域与密文/请求作用域不匹配。 */
    SCOPE_MISMATCH,
    /** 审计写入失败，敏感操作 fail-closed 拒绝。 */
    AUDIT_FAILURE
}
