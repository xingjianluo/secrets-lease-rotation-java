package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 作用域不匹配。 */
public class ScopeMismatchException extends SecretLeaseException {
    public ScopeMismatchException(String message) {
        super(DenyReason.SCOPE_MISMATCH, message);
    }

    public ScopeMismatchException(String message, Throwable cause) {
        super(DenyReason.SCOPE_MISMATCH, message, cause);
    }
}
