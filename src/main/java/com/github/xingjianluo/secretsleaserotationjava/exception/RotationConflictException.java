package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 并发轮换冲突。 */
public class RotationConflictException extends SecretLeaseException {
    public RotationConflictException(String message) {
        super(DenyReason.ROTATION_IN_PROGRESS, message);
    }

    public RotationConflictException(String message, Throwable cause) {
        super(DenyReason.ROTATION_IN_PROGRESS, message, cause);
    }
}
