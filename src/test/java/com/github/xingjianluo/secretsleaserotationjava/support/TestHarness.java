package com.github.xingjianluo.secretsleaserotationjava.support;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditSink;
import com.github.xingjianluo.secretsleaserotationjava.audit.InMemoryAuditSink;
import com.github.xingjianluo.secretsleaserotationjava.config.AppProperties;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalKeyManager;
import com.github.xingjianluo.secretsleaserotationjava.lease.LeaseStore;
import com.github.xingjianluo.secretsleaserotationjava.service.DefaultSecretService;
import com.github.xingjianluo.secretsleaserotationjava.service.SecretService;
import java.time.Duration;
import java.time.Instant;

/**
 * 测试装配：把可控时钟、内存组件与真实服务实现组装在一起，
 * 暴露各组件以便断言审计与版本状态。
 */
public record TestHarness(MutableTimeSource clock,
                          LocalKeyManager keyManager,
                          LeaseStore leaseStore,
                          InMemoryAuditSink auditSink,
                          SecretService service) {

    public static TestHarness create(Duration grace, Duration defaultTtl) {
        MutableTimeSource clock = MutableTimeSource.startAt(Instant.parse("2026-09-24T00:00:00Z"));
        return withKeyManager(clock, grace, defaultTtl, new LocalKeyManager(clock, grace));
    }

    public static TestHarness withKeyManager(MutableTimeSource clock, Duration grace,
                                             Duration defaultTtl, LocalKeyManager keyManager) {
        AppProperties properties = new AppProperties(grace, defaultTtl);
        LeaseStore leaseStore = new LeaseStore();
        InMemoryAuditSink auditSink = new InMemoryAuditSink();
        SecretService service = new DefaultSecretService(
                clock, properties, keyManager, leaseStore, auditSink);
        return new TestHarness(clock, keyManager, leaseStore, auditSink, service);
    }
}
