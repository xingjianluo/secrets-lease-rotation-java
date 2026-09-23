package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 密钥版本不存在。 */
public class UnknownKeyVersionException extends SecretLeaseException {
    public UnknownKeyVersionException(String message) {
        super(DenyReason.UNKNOWN_KEY_VERSION, message);
    }

    public UnknownKeyVersionException(String message, Throwable cause) {
        super(DenyReason.UNKNOWN_KEY_VERSION, message, cause);
    }
}
