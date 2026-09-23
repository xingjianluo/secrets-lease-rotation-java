package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditAction;
import com.github.xingjianluo.secretsleaserotationjava.audit.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import com.github.xingjianluo.secretsleaserotationjava.service.LeaseView;
import com.github.xingjianluo.secretsleaserotationjava.service.ReadOutcome;
import com.github.xingjianluo.secretsleaserotationjava.support.TestHarness;
import com.github.xingjianluo.secretsleaserotationjava.support.TestLogger;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * fail-closed 审计策略测试：审计写不进去时敏感操作不得静默放行；
 * 签发/读取/轮换/撤销四类动作均关联主体、作用域、密钥版本与结果。
 */
class AuditPolicyTests {

    private final TestHarness h = TestHarness.create(Duration.ofMinutes(2), Duration.ofMinutes(5));

    @Test
    void successfulReadIsClosedWhenAuditSinkFails() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        String cipher = h.service().seal("top-secret");

        TestLogger.given("READ_FAIL_CLOSED",
                "alice 持有有效 payroll 租约且密文有效", "审计存储被置为下 1 次写入失败");
        h.auditSink().failNextWrites(1);
        ServiceException ex = assertThrows(ServiceException.class,
                () -> h.service().read(lease.token(), "payroll", cipher));
        assertEquals(Reason.AUDIT_FAILURE, ex.reason());
        TestLogger.decided("READ_FAIL_CLOSED",
                "成功审计写不进去 -> fail-closed 拒绝原因=" + ex.reason() + "，明文不得释放");
    }

    @Test
    void issueIsRejectedWhenAuditSinkFailsAndLeaseNotVisible() {
        h.service().registerSubject("alice");
        h.auditSink().failNextWrites(1);
        TestLogger.given("ISSUE_AUDIT_DOWN", "alice 合法，但签发审计写入失败");
        ServiceException ex = assertThrows(ServiceException.class,
                () -> h.service().issueLease("alice", "payroll", Duration.ofMinutes(5)));
        assertEquals(Reason.AUDIT_FAILURE, ex.reason());
        assertEquals(0, h.leaseStore().size(), "审计失败的租约不得可见");
        TestLogger.decided("ISSUE_AUDIT_DOWN", "拒绝原因=" + ex.reason() + "，无租约残留");
    }

    @Test
    void everyActionAuditsSubjectScopeVersionAndResult() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        String cipher = h.service().seal("m");
        h.service().read(lease.token(), "payroll", cipher);
        h.service().rotate();
        h.service().revoke(lease.token());

        AuditEvent issue = find(AuditAction.ISSUE);
        AuditEvent read = find(AuditAction.READ);
        AuditEvent rotate = find(AuditAction.ROTATE);
        AuditEvent revoke = find(AuditAction.REVOKE);

        TestLogger.given("AUDIT_CONTENT", "顺序执行 签发/读取/轮换/撤销");
        TestLogger.decided("AUDIT_CONTENT",
                "ISSUE subject=" + issue.subject() + " scope=" + issue.scope()
                        + " v" + issue.keyVersion() + " result=" + issue.result());
        assertEquals("alice", read.subject());
        assertEquals("payroll", read.scope());
        assertTrue(read.keyVersion() >= 1);
        assertEquals(com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult.ALLOW,
                read.result());
        assertEquals("system", rotate.subject());
        assertEquals(2, rotate.keyVersion());
        assertEquals("alice", revoke.subject());
        assertEquals("payroll", revoke.scope());
    }

    @Test
    void deniedReadIsAlsoAuditedEvenWhenNothingIsReturned() {
        h.service().registerSubject("alice");
        LeaseView lease = h.service().issueLease("alice", "payroll", Duration.ofMinutes(5));
        h.service().revoke(lease.token());
        h.auditSink().clear();

        TestLogger.given("DENY_AUDITED", "撤销后读取必须被拒绝且留痕");
        ReadOutcome outcome = h.service().read(lease.token(), "payroll", h.service().seal("x"));
        assertInstanceOf(ReadOutcome.Denied.class, outcome);
        AuditEvent event = h.auditSink().events().get(0);
        assertEquals(AuditAction.READ, event.action());
        assertEquals(com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult.DENY_LEASE_REVOKED,
                event.result());
        TestLogger.decided("DENY_AUDITED", "审计结果=" + event.result());
    }

    private AuditEvent find(AuditAction action) {
        return h.auditSink().events().stream()
                .filter(e -> e.action() == action)
                .findFirst().orElseThrow();
    }
}
