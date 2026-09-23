package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 租约已过期。 */
public class LeaseExpiredException extends SecretLeaseException {
    public LeaseExpiredException(String message) {
        super(DenyReason.LEASE_EXPIRED, message);
    }

    public LeaseExpiredException(String message, Throwable cause) {
        super(DenyReason.LEASE_EXPIRED, message, cause);
    }
}
