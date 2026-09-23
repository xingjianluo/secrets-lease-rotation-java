package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/**
 * 所有可预期拒绝的统一基类。携带可区分的 {@link DenyReason}，
 * 保证服务门面与 REST 入口得到一致、可解释的结论。
 */
public class SecretLeaseException extends RuntimeException {

    private final DenyReason reason;

    public SecretLeaseException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SecretLeaseException(DenyReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }
}
