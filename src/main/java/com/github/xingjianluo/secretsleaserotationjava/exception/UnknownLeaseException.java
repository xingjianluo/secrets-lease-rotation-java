package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 租约不存在。 */
public class UnknownLeaseException extends SecretLeaseException {
    public UnknownLeaseException(String message) {
        super(DenyReason.UNKNOWN_LEASE, message);
    }

    public UnknownLeaseException(String message, Throwable cause) {
        super(DenyReason.UNKNOWN_LEASE, message, cause);
    }
}
