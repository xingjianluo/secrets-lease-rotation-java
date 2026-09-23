package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 主体不存在。 */
public class UnknownSubjectException extends SecretLeaseException {
    public UnknownSubjectException(String message) {
        super(DenyReason.UNKNOWN_SUBJECT, message);
    }

    public UnknownSubjectException(String message, Throwable cause) {
        super(DenyReason.UNKNOWN_SUBJECT, message, cause);
    }
}
