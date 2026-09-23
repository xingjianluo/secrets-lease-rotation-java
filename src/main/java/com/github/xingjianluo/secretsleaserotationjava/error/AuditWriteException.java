package com.github.xingjianluo.secretsleaserotationjava.error;

/**
 * 审计存储写入失败时由 AuditSink 抛出，服务层必须将其转换为 fail-closed 拒绝。
 */
public class AuditWriteException extends RuntimeException {
    public AuditWriteException(String message) {
        super(message);
    }

    public AuditWriteException(String message, Throwable cause) {
        super(message, cause);
    }
}
