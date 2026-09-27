package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.AuditFailureException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 退役版本清理：
 * 前置条件（当前版本/宽限期未到/不存在/已清理）被明确拒绝；
 * 清理后读与升级得到 KEY_VERSION_PURGED，不会被当前版本顶替；
 * 清理动作可追溯；审计写失败时状态不变（fail-closed）。
 */
class PurgeTests {

    private static final Logger log = LoggerFactory.getLogger(PurgeTests.class);

    @Test
    void purgePreconditionsAreEnforced() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.issueLease("alice", "payroll", Duration.ofHours(200));

        // 当前版本 v1 不许清理
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionNotPurgeableException.class)
                .satisfies(e -> log.info("[前置-当前版本] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 不存在的版本：UNKNOWN_KEY_VERSION
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(42))
                .isInstanceOf(UnknownKeyVersionException.class)
                .satisfies(e -> log.info("[前置-不存在] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        RotateResult rot = infra.service.rotate(Duration.ofHours(24));
        log.info("轮换 v{} -> v{}，v1 进入宽限期", rot.previousVersion(), rot.newVersion());

        // 宽限期未到（T0）：v1 不许清理
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionNotPurgeableException.class)
                .satisfies(e -> log.info("[前置-宽限期内] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 临界前一刻仍不许
        infra.advance(Duration.ofHours(24).minusMinutes(1));
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionNotPurgeableException.class);

        // 当前版本（现在的 v2）依旧不许清理
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(2))
                .isInstanceOf(KeyVersionNotPurgeableException.class);
    }

    @Test
    void purgeAfterGraceRemovesMaterialAndReadAndUpgradeReportPurged() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        EncryptResult encV1 = infra.service.encrypt("payroll", "old-secret");
        infra.service.rotate(Duration.ofHours(24));
        EncryptResult encV2 = infra.service.encrypt("payroll", "new-secret");

        // 到宽限截止时刻：读 v1 是 GRACE_EXPIRED（尚不能用当前版本顶替）
        infra.advance(Duration.ofHours(24));
        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), encV1.ciphertext()))
                .isInstanceOf(KeyGraceExpiredException.class);

        PurgeResult purged = infra.service.purgeKeyVersion(1);
        log.info("[清理成功] v{} purgedAt={} graceDeadline={}",
                purged.version(), purged.purgedAt(), purged.graceDeadline());
        assertThat(purged.version()).isEqualTo(1);
        assertThat(infra.keyStore.findVersion(1)).isEmpty();
        assertThat(infra.keyStore.findPurged(1)).isPresent();

        // 清理后再读 v1：KEY_VERSION_PURGED（与"从未存在"区分，且不拿 v2 顶替）
        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), encV1.ciphertext()))
                .isInstanceOf(KeyVersionPurgedException.class)
                .satisfies(e -> log.info("[清理后读取] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 清理后再升级 v1：同样明确拒绝
        assertThatThrownBy(() -> infra.service.upgrade(lease.leaseId(), encV1.ciphertext()))
                .isInstanceOf(KeyVersionPurgedException.class)
                .satisfies(e -> log.info("[清理后升级] 判定={}", ((SecretLeaseException) e).reason()));

        // 当前版本 v2 完全不受影响
        assertThat(infra.service.read(lease.leaseId(), encV2.ciphertext()).plaintext())
                .isEqualTo("new-secret");

        // 重复清理：NOT_PURGEABLE（已被清理，不能重复）
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionNotPurgeableException.class)
                .satisfies(e -> log.info("[重复清理] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 清理动作可追溯：成功审计 + 墓碑可查
        AuditEvent successAudit = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION && "SUCCESS".equals(e.result()))
                .findFirst().orElseThrow();
        assertThat(successAudit.keyVersion()).isEqualTo(1);
        List<?> deniedPurges = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION
                        && e.result().equals("DENIED:" + DenyReason.KEY_VERSION_NOT_PURGEABLE.name()))
                .toList();
        assertThat(deniedPurges).isNotEmpty();
        log.info("[清理追溯] 成功审计 detail={}；拒绝清理条数={}",
                successAudit.detail(), deniedPurges.size());
    }

    @Test
    void auditFailureKeepsPurgeFromChangingState() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.rotate(Duration.ZERO);
        infra.advance(Duration.ofMillis(1));

        // 让本次清理的"提交前审计"失败：必须 fail-closed，密钥材料不得被移除
        infra.auditSink.failNext();
        long eventsBefore = infra.auditEvents().size();
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(AuditFailureException.class)
                .satisfies(e -> log.info("[清理-审计失败] 判定={} msg={}",
                        ((AuditFailureException) e).reason(), e.getMessage()));

        assertThat(infra.keyStore.findVersion(1))
                .as("审计失败时状态不得改变：v1 密钥材料仍在")
                .isPresent();
        assertThat(infra.keyStore.findPurged(1)).isEmpty();
        assertThat(infra.auditEvents()).hasSize((int) eventsBefore);
        log.info("[清理-审计失败] v1 仍存活，无墓碑，无状态漂移");

        // 审计恢复后重试应成功
        PurgeResult retried = infra.service.purgeKeyVersion(1);
        assertThat(retried.version()).isEqualTo(1);
        assertThat(infra.keyStore.findPurged(1)).isPresent();
        log.info("[清理-审计恢复] 重试成功，v1 已清理");
    }
}
