package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.AuditFailureException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 新路径（升级 / 清理）的审计完整性：
 * 成功与拒绝都留痕；审计写失败时 fail-closed——升级不吐新密文、清理不动状态。
 */
class UpgradePurgeAuditTests {

    private static final Logger log = LoggerFactory.getLogger(UpgradePurgeAuditTests.class);

    @Test
    void upgradeSuccessAndDenialAreBothAudited() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1 = infra.service.encrypt("payroll", "audited");
        infra.service.rotate(Duration.ofHours(24));

        UpgradeResult ok = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
        AuditEvent success = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_CIPHERTEXT && "SUCCESS".equals(e.result()))
                .findFirst().orElseThrow();
        assertThat(success.leaseId()).isEqualTo(lease.leaseId());
        assertThat(success.subject()).isEqualTo("alice");
        assertThat(success.scope()).isEqualTo("payroll");
        assertThat(success.keyVersion()).isEqualTo(ok.targetVersion());
        log.info("升级成功审计: v{} result={} detail={}", success.keyVersion(),
                success.result(), success.detail());

        // 未知租约升级必须被拒绝且留痕
        assertThatThrownBy(() -> infra.service.upgrade("missing", v1.ciphertext()))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException.class);
        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_CIPHERTEXT && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(denied.result()).isEqualTo("DENIED:UNKNOWN_LEASE");
        log.info("升级拒绝审计: result={} detail={}", denied.result(), denied.detail());
    }

    @Test
    void auditFailureDuringUpgradeDeniesAndReturnsNoNewCiphertext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1 = infra.service.encrypt("payroll", "no-leak-upgrade");
        infra.service.rotate(Duration.ofHours(24));

        long eventsBefore = infra.auditEvents().size();
        infra.auditSink.failNext(); // 唯一一次审计是成功结论 -> 失败
        assertThatThrownBy(() -> infra.service.upgrade(lease.leaseId(), v1.ciphertext()))
                .isInstanceOf(AuditFailureException.class)
                .satisfies(e -> log.info("升级 fail-closed 判定={} msg={}",
                        ((AuditFailureException) e).reason(), e.getMessage()));

        // 没有产生成功升级记录；且再读原密文仍落在 v1（状态/密文未受任何影响）
        assertThat(infra.auditEvents()).hasSize((int) eventsBefore);
        assertThat(infra.service.read(lease.leaseId(), v1.ciphertext()).keyVersion())
                .isEqualTo(1);
        log.info("审计恢复后原密文仍按 v1 读取，升级未泄漏任何新密文");
    }

    @Test
    void purgeIsAuditedAndAuditFailureLeavesStateUntouched() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1 = infra.service.encrypt("payroll", "p");
        infra.service.rotate(Duration.ofHours(24));
        infra.advance(Duration.ofHours(24));

        // 审计失败：清理必须中止，版本不得变成墓碑（状态原样保留）
        infra.auditSink.failNext();
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(AuditFailureException.class);
        assertThat(infra.keyStore.findVersion(1)).isPresent();
        assertThat(infra.keyStore.findVersion(1).orElseThrow().isPurged())
                .as("审计失败时清理必须中止，版本仍是未清理状态").isFalse();
        log.info("清理审计失败后状态未变：v1 仍在库中且非墓碑");

        // 审计恢复后再次清理成功，且可追溯
        PurgeResult purged = infra.service.purgeKeyVersion(1);
        assertThat(purged.version()).isEqualTo(1);
        List<AuditEvent> purgeEvents = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION).toList();
        assertThat(purgeEvents).anySatisfy(e -> {
            assertThat(e.result()).isEqualTo("SUCCESS");
            assertThat(e.keyVersion()).isEqualTo(1);
        });
        log.info("清理成功审计可追溯: {}", purgeEvents);
    }
}
