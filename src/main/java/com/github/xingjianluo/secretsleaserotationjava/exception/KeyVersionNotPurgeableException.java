package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 退役版本宽限期尚未结束（或版本当前不允许清理）。 */
public class KeyVersionNotPurgeableException extends SecretLeaseException {
    public KeyVersionNotPurgeableException(String message) {
        super(DenyReason.KEY_VERSION_NOT_PURGEABLE, message);
    }

    public KeyVersionNotPurgeableException(String message, Throwable cause) {
        super(DenyReason.KEY_VERSION_NOT_PURGEABLE, message, cause);
    }
}
