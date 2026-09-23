package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditSink;
import com.github.xingjianluo.secretsleaserotationjava.audit.InMemoryAuditSink;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.service.LeaseStore;
import com.github.xingjianluo.secretsleaserotationjava.service.ManagedKeyStore;
import com.github.xingjianluo.secretsleaserotationjava.service.SecretLeaseService;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

/**
 * 测试公共设施：可控时钟 + 手工装配一套组件。
 * 通过 {@link #advance} 精确推进时间，用于宽限期/过期的边界断言，杜绝真实 sleep 造成的抖动。
 */
final class TestInfra {

    /** 固定起点，保证测试可复现。 */
    static final Instant T0 = Instant.parse("2026-09-24T00:00:00Z");

    private final MutableClock clock;
    final ManagedKeyStore keyStore;
    final LeaseStore leaseStore;
    final LocalCryptoService crypto;
    final InMemoryAuditSink auditSink;
    final SecretLeaseService service;

    private TestInfra(MutableClock clock, ManagedKeyStore keyStore, LeaseStore leaseStore,
                      LocalCryptoService crypto, InMemoryAuditSink auditSink,
                      SecretLeaseService service) {
        this.clock = clock;
        this.keyStore = keyStore;
        this.leaseStore = leaseStore;
        this.crypto = crypto;
        this.auditSink = auditSink;
        this.service = service;
    }

    static TestInfra newInfra() {
        return newInfra(new LocalCryptoService());
    }

    static TestInfra newInfra(LocalCryptoService crypto) {
        MutableClock clock = new MutableClock(T0, ZoneOffset.UTC);
        ManagedKeyStore keyStore = new ManagedKeyStore(clock, crypto);
        LeaseStore leaseStore = new LeaseStore();
        InMemoryAuditSink auditSink = new InMemoryAuditSink();
        SecretLeaseService service = new SecretLeaseService(
                keyStore, leaseStore, crypto, auditSink, clock);
        return new TestInfra(clock, keyStore, leaseStore, crypto, auditSink, service);
    }

    Instant now() {
        return clock.instant();
    }

    void advance(Duration d) {
        clock.advance(d);
    }

    List<AuditEvent> auditEvents() {
        return auditSink.events();
    }

    long auditCount(Action action) {
        return auditSink.events().stream().filter(e -> e.action() == action).count();
    }

    /** 可手动推进的时钟。 */
    static final class MutableClock extends Clock {
        private Instant instant;
        private final ZoneId zone;

        MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        void advance(Duration d) {
            this.instant = instant.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
