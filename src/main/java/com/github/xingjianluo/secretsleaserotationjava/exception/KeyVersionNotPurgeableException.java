package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 清理密钥版本的前置条件不满足（当前版本 / 宽限期未到 / 版本不存在或已清理）。 */
public class KeyVersionNotPurgeableException extends SecretLeaseException {
    public KeyVersionNotPurgeableException(String message) {
        super(DenyReason.KEY_VERSION_NOT_PURGEABLE, message);
    }

    public KeyVersionNotPurgeableException(String message, Throwable cause) {
        super(DenyReason.KEY_VERSION_NOT_PURGEABLE, message, cause);
    }
}
