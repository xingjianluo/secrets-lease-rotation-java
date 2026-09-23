package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditAction;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import com.github.xingjianluo.secretsleaserotationjava.service.LeaseView;
import com.github.xingjianluo.secretsleaserotationjava.service.ReadOutcome;
import com.github.xingjianluo.secretsleaserotationjava.support.TestHarness;
import com.github.xingjianluo.secretsleaserotationjava.support.TestLogger;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * 租约签发/读取的各类拒绝原因与审计留痕测试。
 */
class LeaseAccessTests {

    private final TestHarness h = TestHarness.create(Duration.ofMinutes(2), Duration.ofMinutes(5));

    @Test
    void validLeaseReadsPlaintext() {
        h.service().registerSubject("alice");
        String cipher = h.service().seal("payroll-2026");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        TestLogger.given("VALID_READ",
                "主体=alice(已注册)", "作用域=payroll", "TTL=5m", "密文=当前版本加密");
        ReadOutcome outcome = h.service().read(lease.token(), "payroll", cipher);
        ReadOutcome.Success success = assertInstanceOf(ReadOutcome.Success.class, outcome);
        assertEquals("payroll-2026", success.plaintext());
        TestLogger.decided("VALID_READ", "ALLOW，明文已释放，使用密钥版本=" + success.keyVersionUsed());
        assertAudit(AuditAction.READ, "alice", "payroll", AuditResult.ALLOW);
    }

    @Test
    void issueForUnknownSubjectIsRejected() {
        TestLogger.given("ISSUE_UNKNOWN_SUBJECT", "主体=bob 未注册，尝试签发 payroll 作用域租约");
        ServiceException ex = assertThrows(ServiceException.class,
                () -> h.service().issueLease("bob", "payroll", Duration.ofMinutes(1)));
        assertEquals(Reason.UNKNOWN_SUBJECT, ex.reason());
        TestLogger.decided("ISSUE_UNKNOWN_SUBJECT", "拒绝原因=" + ex.reason() + "，且不产生租约");
        assertEquals(0, h.leaseStore().size());
    }

    @Test
    void readWithUnknownLeaseIsRejectedAndAudited() {
        TestLogger.given("UNKNOWN_LEASE", "传入不存在的租约 token");
        ReadOutcome outcome = h.service().read("nope", "payroll", "mlcv1:1:AA:AA");
        ReadOutcome.Denied denied = assertInstanceOf(ReadOutcome.Denied.class, outcome);
        assertEquals(Reason.UNKNOWN_LEASE, denied.reason());
        TestLogger.decided("UNKNOWN_LEASE", "拒绝原因=" + denied.reason());
        AuditEvent event = lastEvent();
        assertEquals(AuditAction.READ, event.action());
        assertEquals(AuditResult.DENY_UNKNOWN_LEASE, event.result());
    }

    @Test
    void revokedLeaseIsRejectedAndReadIsAudited() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        h.service().revoke(lease.token());
        TestLogger.given("REVOKED_READ", "alice 的租约已撤销，再次发起读取");
        ReadOutcome outcome = h.service().read(lease.token(), "payroll", h.service().seal("x"));
        ReadOutcome.Denied denied = assertInstanceOf(ReadOutcome.Denied.class, outcome);
        assertEquals(Reason.LEASE_REVOKED, denied.reason());
        TestLogger.decided("REVOKED_READ", "拒绝原因=" + denied.reason() + "（撤销后的读取仍进入审计）");
        assertEquals(AuditResult.DENY_LEASE_REVOKED, lastEvent().result());
        assertEquals("alice", lastEvent().subject());
    }

    @Test
    void expiredLeaseIsRejected() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(1));
        h.clock().advance(Duration.ofMinutes(1));
        TestLogger.given("EXPIRED_READ", "TTL=1m，时钟前进到 expiresAt 边界（到期判定 !now.isBefore(expiresAt)）");
        ReadOutcome outcome = h.service().read(lease.token(), "payroll", h.service().seal("x"));
        ReadOutcome.Denied denied = assertInstanceOf(ReadOutcome.Denied.class, outcome);
        assertEquals(Reason.LEASE_EXPIRED, denied.reason());
        TestLogger.decided("EXPIRED_READ", "拒绝原因=" + denied.reason());
    }

    @Test
    void scopeMismatchIsRejected() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        TestLogger.given("SCOPE_MISMATCH", "租约作用域=payroll，请求作用域=invoices");
        ReadOutcome outcome = h.service().read(lease.token(), "invoices", h.service().seal("x"));
        ReadOutcome.Denied denied = assertInstanceOf(ReadOutcome.Denied.class, outcome);
        assertEquals(Reason.SCOPE_MISMATCH, denied.reason());
        TestLogger.decided("SCOPE_MISMATCH", "拒绝原因=" + denied.reason());
    }

    @Test
    void revokeUnknownLeaseIsRejected() {
        TestLogger.given("REVOKE_UNKNOWN", "撤销不存在的租约");
        ServiceException ex = assertThrows(ServiceException.class, () -> h.service().revoke("ghost"));
        assertEquals(Reason.UNKNOWN_LEASE, ex.reason());
        TestLogger.decided("REVOKE_UNKNOWN", "拒绝原因=" + ex.reason());
    }

    private AuditEvent lastEvent() {
        var events = h.auditSink().events();
        return events.get(events.size() - 1);
    }

    private void assertAudit(AuditAction action, String subject, String scope, AuditResult result) {
        boolean matched = h.auditSink().events().stream()
                .anyMatch(e -> e.action() == action
                        && subject.equals(e.subject())
                        && scope.equals(e.scope())
                        && e.result() == result);
        org.junit.jupiter.api.Assertions.assertTrue(matched,
                "expected audit " + action + "/" + subject + "/" + scope + "/" + result
                        + " but got " + h.auditSink().events());
    }
}
