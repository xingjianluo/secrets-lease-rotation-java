package com.github.xingjianluo.secretsleaserotationjava.service;

import java.time.Duration;

/**
 * 本地密钥托管 + 租约访问统一门面，所有入口（HTTP 等）都经由本类以保证结论一致、审计完整。
 */
public interface SecretService {

    /** 注册可被签发租约的主体（管理操作）。 */
    void registerSubject(String subject);

    /** 使用当前密钥版本加密明文（管理操作，便于测试/演示）。 */
    String seal(String plaintext);

    /** 当前密钥版本号。 */
    int currentKeyVersion();

    /**
     * 为主体在指定作用域签发短期租约。主体不存在须以 UNKNOWN_SUBJECT 拒绝。
     */
    LeaseView issueLease(String subject, String scope, Duration ttl);

    /**
     * 凭租约读取密文：依次校验租约存在、撤销、过期、作用域匹配，再按密钥版本/宽限期解密。
     * 成功返回 {@link ReadOutcome.Success}，可区分原因的拒绝返回 {@link ReadOutcome.Denied}，
     * 绝不静默降级或跨主体串用。
     */
    ReadOutcome read(String leaseToken, String scope, String ciphertext);

    /**
     * 轮换密钥：并发调用仅一个成功，冲突者得到 {@link RotationOutcome.Conflict} 且无中间状态。
     */
    RotationOutcome rotate();

    /** 撤销租约；不存在的租约须以 UNKNOWN_LEASE 拒绝。 */
    void revoke(String leaseToken);
}
