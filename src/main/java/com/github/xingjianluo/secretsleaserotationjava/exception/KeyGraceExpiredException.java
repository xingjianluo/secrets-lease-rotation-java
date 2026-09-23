package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 旧密钥版本宽限期已结束。 */
public class KeyGraceExpiredException extends SecretLeaseException {
    public KeyGraceExpiredException(String message) {
        super(DenyReason.KEY_VERSION_GRACE_EXPIRED, message);
    }

    public KeyGraceExpiredException(String message, Throwable cause) {
        super(DenyReason.KEY_VERSION_GRACE_EXPIRED, message, cause);
    }
}
