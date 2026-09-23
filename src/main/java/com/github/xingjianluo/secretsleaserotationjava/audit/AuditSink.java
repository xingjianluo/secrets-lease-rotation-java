package com.github.xingjianluo.secretsleaserotationjava.audit;

/**
 * 审计出口。写入失败必须抛出 {@link com.github.xingjianluo.secretsleaserotationjava.error.AuditWriteException}，
 * 由服务层按 fail-closed 处理。
 */
public interface AuditSink {
    void write(AuditEvent event);
}
