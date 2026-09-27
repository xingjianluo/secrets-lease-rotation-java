package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 密钥版本曾存在但已被清理移出托管库。 */
public class KeyVersionPurgedException extends SecretLeaseException {
    public KeyVersionPurgedException(String message) {
        super(DenyReason.KEY_VERSION_PURGED, message);
    }

    public KeyVersionPurgedException(String message, Throwable cause) {
        super(DenyReason.KEY_VERSION_PURGED, message, cause);
    }
}
