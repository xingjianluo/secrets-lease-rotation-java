package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 租约已撤销。 */
public class LeaseRevokedException extends SecretLeaseException {
    public LeaseRevokedException(String message) {
        super(DenyReason.LEASE_REVOKED, message);
    }

    public LeaseRevokedException(String message, Throwable cause) {
        super(DenyReason.LEASE_REVOKED, message, cause);
    }
}
