package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 审计写入失败。 */
public class AuditFailureException extends SecretLeaseException {
    public AuditFailureException(String message) {
        super(DenyReason.AUDIT_FAILURE, message);
    }

    public AuditFailureException(String message, Throwable cause) {
        super(DenyReason.AUDIT_FAILURE, message, cause);
    }
}
