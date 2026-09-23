package com.github.xingjianluo.secretsleaserotationjava.audit;

import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;

import java.util.List;

/** 审计落库抽象。 */
public interface AuditSink {

    /** 追加一条审计记录；写入失败必须抛出异常，由上层 fail-closed 处理。 */
    void append(AuditEvent event);

    /** 已落库的审计记录（只读视图，便于校验）。 */
    List<AuditEvent> events();
}
