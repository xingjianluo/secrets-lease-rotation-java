package com.github.xingjianluo.secretsleaserotationjava.audit;

import com.github.xingjianluo.secretsleaserotationjava.error.AuditWriteException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;

/**
 * 内存审计存储：
 * <ul>
 *   <li>{@link CopyOnWriteArrayList} 保证写入顺序与并发读快照，读者之间不互相影响；</li>
 *   <li>支持 {@link #failNextWrites(int)} 注入连续失败，用于验证 fail-closed：
 *       审计写不进去时，敏感操作必须被拒绝而不是静默放行。</li>
 * </ul>
 */
@Component
public class InMemoryAuditSink implements AuditSink {

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final AtomicInteger remainingFailures = new AtomicInteger(0);

    @Override
    public void write(AuditEvent event) {
        int left = remainingFailures.getAndUpdate(n -> n > 0 ? n - 1 : 0);
        if (left > 0) {
            throw new AuditWriteException("simulated audit storage failure for " + event.action());
        }
        events.add(event);
    }

    /** 按时间顺序返回全部审计事件（快照）。 */
    public List<AuditEvent> events() {
        return List.copyOf(events);
    }

    /** 测试支持：让接下来的 {@code count} 次 write 抛出 AuditWriteException。 */
    public void failNextWrites(int count) {
        remainingFailures.addAndGet(count);
    }

    /** 测试支持：清空已记录事件。 */
    public void clear() {
        events.clear();
    }
}
