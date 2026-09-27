package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/** 密文格式可解析，但完整性校验失败（密钥不符或内容被篡改）。 */
public class CiphertextInvalidException extends SecretLeaseException {
    public CiphertextInvalidException(String message) {
        super(DenyReason.CIPHERTEXT_INVALID, message);
    }

    public CiphertextInvalidException(String message, Throwable cause) {
        super(DenyReason.CIPHERTEXT_INVALID, message, cause);
    }
}
