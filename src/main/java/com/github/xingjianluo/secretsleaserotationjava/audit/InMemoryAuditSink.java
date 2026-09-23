package com.github.xingjianluo.secretsleaserotationjava.audit;

import com.github.xingjianluo.secretsleaserotationjava.exception.AuditFailureException;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 进程内审计实现，线程安全。
 * 可通过 {@link #failNext()} 注入下一次写入故障，用于验证 fail-closed 语义：
 * 审计写不进去时，敏感读取/签发/撤销不得被放行。
 */
@Component
public class InMemoryAuditSink implements AuditSink {

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();
    private volatile boolean failNext = false;

    @Override
    public void append(AuditEvent event) {
        if (failNext) {
            failNext = false;
            throw new AuditFailureException("模拟审计落库失败");
        }
        events.add(event);
    }

    @Override
    public List<AuditEvent> events() {
        return List.copyOf(events);
    }

    /** 令下一次 append 抛出 {@link AuditFailureException}（测试用）。 */
    public void failNext() {
        this.failNext = true;
    }
}
