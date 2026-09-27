package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.AuditFailureException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 审计完整性：签发/读取/轮换/撤销均留痕并关联主体、作用域、密钥版本与结果；
 * 审计写入失败时敏感读取 fail-closed；撤销后的拒绝读取同样进审计。
 */
class AuditTests {

    private static final Logger log = LoggerFactory.getLogger(AuditTests.class);

    @Test
    void everyActionIsAuditedWithSubjectScopeVersionAndResult() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        EncryptResult enc = infra.service.encrypt("payroll", "s-1");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        infra.service.read(lease.leaseId(), enc.ciphertext());
        infra.service.rotate(Duration.ofHours(2));
        infra.service.revoke(lease.leaseId());

        List<AuditEvent> events = infra.auditEvents();
        log.info("审计事件序列:");
        events.forEach(e -> log.info("  {} subject={} scope={} v{} lease={} result={}",
                e.action(), e.subject(), e.scope(), e.keyVersion(),
                abbrev(e.leaseId()), e.result()));

        assertThat(infra.auditCount(Action.ENCRYPT_SECRET)).isEqualTo(1);
        assertThat(infra.auditCount(Action.ISSUE_LEASE)).isEqualTo(1);
        assertThat(infra.auditCount(Action.READ_SECRET)).isEqualTo(1);
        assertThat(infra.auditCount(Action.ROTATE)).isEqualTo(1);
        assertThat(infra.auditCount(Action.REVOKE_LEASE)).isEqualTo(1);

        AuditEvent read = events.stream().filter(e -> e.action() == Action.READ_SECRET).findFirst().orElseThrow();
        assertThat(read.subject()).isEqualTo("alice");
        assertThat(read.scope()).isEqualTo("payroll");
        assertThat(read.keyVersion()).isEqualTo(1);
        assertThat(read.leaseId()).isEqualTo(lease.leaseId());
        assertThat(read.result()).isEqualTo("SUCCESS");

        AuditEvent rotate = events.stream().filter(e -> e.action() == Action.ROTATE).findFirst().orElseThrow();
        assertThat(rotate.result()).isEqualTo("SUCCESS");
        assertThat(rotate.keyVersion()).isEqualTo(2);

        AuditEvent revoke = events.stream().filter(e -> e.action() == Action.REVOKE_LEASE).findFirst().orElseThrow();
        assertThat(revoke.subject()).isEqualTo("alice");
        assertThat(revoke.scope()).isEqualTo("payroll");
        assertThat(revoke.result()).isEqualTo("SUCCESS");
    }

    @Test
    void auditFailureDeniesSensitiveReadAndReturnsNoPlaintext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        EncryptResult enc = infra.service.encrypt("payroll", "do-not-leak");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));

        // 让本次读取的"审计写入"失败：即便所有业务校验都通过，也必须拒绝，不得返回明文
        infra.auditSink.failNext();
        long before = infra.auditEvents().size();
        assertThatThrownBy(() -> {
                    log.info("fail-closed 输入: leaseId={}（审计将注入失败）", lease.leaseId());
                    infra.service.read(lease.leaseId(), enc.ciphertext());
                })
                .isInstanceOf(AuditFailureException.class)
                .satisfies(e -> log.info("fail-closed 判定={} msg={}",
                        ((AuditFailureException) e).reason(), e.getMessage()));

        // 失败的审计记录本身没有落库，且没有产生任何成功读取记录
        assertThat(infra.auditEvents()).hasSize((int) before);
        boolean leakedSuccessRead = infra.auditEvents().stream()
                .anyMatch(e -> e.action() == Action.READ_SECRET && "SUCCESS".equals(e.result()));
        assertThat(leakedSuccessRead).as("审计失败时不得留下成功读取，更不得放行明文").isFalse();

        // 审计恢复后同一租约可正常读取
        assertThat(infra.service.read(lease.leaseId(), enc.ciphertext()).plaintext())
                .isEqualTo("do-not-leak");
        log.info("审计恢复后读取正常，证明拒绝确由审计故障导致");
    }

    @Test
    void readAfterRevocationIsRecordedInAuditAsDenied() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        EncryptResult enc = infra.service.encrypt("payroll", "s-2");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        infra.service.revoke(lease.leaseId());

        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), enc.ciphertext()))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception.LeaseRevokedException.class);

        AuditEvent deniedRead = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.READ_SECRET && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        log.info("撤销后读取审计: scope={} v{} lease={} result={} detail={}",
                deniedRead.scope(), deniedRead.keyVersion(), abbrev(deniedRead.leaseId()),
                deniedRead.result(), deniedRead.detail());
        assertThat(deniedRead.result()).isEqualTo("DENIED:LEASE_REVOKED");
        assertThat(deniedRead.leaseId()).isEqualTo(lease.leaseId());
        assertThat(deniedRead.keyVersion()).isEqualTo(1);
    }

    private static String abbrev(String s) {
        return s == null ? null : s.substring(0, Math.min(8, s.length())) + "..";
    }

    @Test
    void upgradeIsAuditedAndAuditFailureReleasesNoNewCiphertext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        EncryptResult enc = infra.service.encrypt("payroll", "upgrade-me");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        infra.service.rotate(Duration.ofHours(24));

        // 审计写不进去：即便校验全过、新密文已在内存算出，也必须 fail-closed，绝不吐出新密文
        infra.auditSink.failNext();
        long before = infra.auditEvents().size();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> {
                    log.info("升级 fail-closed 输入: leaseId={}（审计将注入失败）", lease.leaseId());
                    infra.service.upgrade(lease.leaseId(), enc.ciphertext());
                })
                .isInstanceOf(AuditFailureException.class)
                .satisfies(e -> log.info("升级 fail-closed 判定={} msg={}",
                        ((AuditFailureException) e).reason(), e.getMessage()));
        assertThat(infra.auditEvents()).hasSize((int) before);
        boolean leaked = infra.auditEvents().stream()
                .anyMatch(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()));
        assertThat(leaked).as("审计失败时不得有成功升级记录，更不得返回新密文").isFalse();

        // 审计恢复后升级成功，留痕关联主体/作用域/目标版本/租约
        var up = infra.service.upgrade(lease.leaseId(), enc.ciphertext());
        AuditEvent success = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .findFirst().orElseThrow();
        log.info("升级成功审计: subject={} scope={} v{} lease={} detail={}",
                success.subject(), success.scope(), success.keyVersion(),
                abbrev(success.leaseId()), success.detail());
        assertThat(success.subject()).isEqualTo("alice");
        assertThat(success.scope()).isEqualTo("payroll");
        assertThat(success.keyVersion()).isEqualTo(up.targetVersion()).isEqualTo(2);
        assertThat(success.leaseId()).isEqualTo(lease.leaseId());
    }

    @Test
    void deniedUpgradeAndPurgeAreRecordedWithDecisionBasis() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult enc = infra.service.encrypt("payroll", "s");

        // 宽限期为 0 轮换并推进时间后，旧 v1 密文升级应被 GRACE_EXPIRED 拒绝并留痕
        infra.service.rotate(Duration.ZERO);
        infra.advance(Duration.ofMillis(1));
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> infra.service.upgrade(lease.leaseId(), enc.ciphertext()))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException.class);
        AuditEvent deniedUpgrade = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(deniedUpgrade.result()).isEqualTo("DENIED:KEY_VERSION_GRACE_EXPIRED");
        assertThat(deniedUpgrade.leaseId()).isEqualTo(lease.leaseId());
        log.info("升级拒绝审计: result={} detail={}", deniedUpgrade.result(), deniedUpgrade.detail());

        // 清理当前版本 v2 必须被拒绝并留痕
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> infra.service.purgeKeyVersion(2))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException.class);
        AuditEvent deniedPurge = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(deniedPurge.result()).isEqualTo("DENIED:KEY_VERSION_NOT_PURGEABLE");
        assertThat(deniedPurge.keyVersion()).isEqualTo(2);
        log.info("清理拒绝审计: result={} detail={}", deniedPurge.result(), deniedPurge.detail());

        // 清理成功留痕
        infra.service.purgeKeyVersion(1);
        AuditEvent purged = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION && "SUCCESS".equals(e.result()))
                .findFirst().orElseThrow();
        assertThat(purged.keyVersion()).isEqualTo(1);
        assertThat(purged.detail()).contains("移出密钥材料");
    }
}
