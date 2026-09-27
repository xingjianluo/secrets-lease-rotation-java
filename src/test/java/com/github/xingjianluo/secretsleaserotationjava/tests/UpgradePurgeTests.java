package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.CiphertextInvalidException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeItemResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 顺序场景：密文升级（宽限期内/临界点/篡改/租约关）与退役版本清理（前置条件/清理后读取）。
 * 每个用例都打印输入与判定依据。
 */
class UpgradePurgeTests {

    private static final Logger log = LoggerFactory.getLogger(UpgradePurgeTests.class);

    private static String head(String ct) {
        return ct == null ? "null" : ct.substring(0, Math.min(18, ct.length())) + "...";
    }

    /** 篡改 GCM 密文体（翻转一个字节），保留版本与作用域前缀。 */
    private static String tamper(String ciphertext) {
        String[] parts = ciphertext.split(":", 3);
        byte[] body = Base64.getDecoder().decode(parts[2]);
        body[body.length - 1] ^= 0x01;
        return parts[0] + ":" + parts[1] + ":" + Base64.getEncoder().encodeToString(body);
    }

    private SecretLeaseException expectUpgradeDeny(TestInfra infra, String leaseId, List<String> cts,
                                                   com.github.xingjianluo.secretsleaserotationjava.model.DenyReason reason,
                                                   String desc) {
        log.info("[{}] 输入 leaseId={}, 密文头={}", desc, leaseId,
                cts.stream().map(UpgradePurgeTests::head).toList());
        try {
            infra.service.upgradeBatch(leaseId, cts);
        } catch (SecretLeaseException e) {
            log.info("[{}] 判定依据={}（期望 {}）msg={}", desc, e.reason(), reason, e.getMessage());
            assertThat(e.reason()).isEqualTo(reason);
            return e;
        }
        throw new AssertionError("[" + desc + "] 期望被拒绝(" + reason + ")但升级成功");
    }

    @Test
    void upgradeWithinGraceMovesCiphertextToCurrentVersion() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1enc = infra.service.encrypt("payroll", "salary-4242");
        log.info("用例-宽限期内升级: 初始密文 v{}", v1enc.keyVersion());

        RotateResult rot = infra.service.rotate(Duration.ofHours(24));
        infra.advance(Duration.ofHours(1));
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);

        // 升级：旧 v1 密文 -> 当前 v2
        UpgradeResult up = infra.service.upgrade(lease.leaseId(), v1enc.ciphertext());
        log.info("升级结论: scope={}, {} -> v{}, 新密文头={}", up.scope(),
                up.items().get(0).sourceVersion(), up.targetVersion(),
                head(up.items().get(0).ciphertext()));
        assertThat(up.targetVersion()).isEqualTo(2);
        assertThat(up.items()).hasSize(1);
        assertThat(up.items().get(0).sourceVersion()).isEqualTo(1);
        assertThat(up.scope()).isEqualTo("payroll");
        assertThat(up.items().get(0).ciphertext()).startsWith("v2:payroll:");

        // 用同一个租约再读新密文，落在当前版本，明文完全一致
        SecretReadResult reread = infra.service.read(lease.leaseId(), up.items().get(0).ciphertext());
        assertThat(reread.keyVersion()).isEqualTo(2);
        assertThat(reread.plaintext()).isEqualTo("salary-4242");
        log.info("升级后再读: keyVersion=v{}, plaintext={}", reread.keyVersion(), reread.plaintext());
    }

    @Test
    void batchUpgradesInParallelAndIsAllOrNothing() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        // 准备 32 份不同明文的 v1 密文
        List<String> oldCts = new java.util.ArrayList<>();
        List<String> plains = new java.util.ArrayList<>();
        for (int i = 0; i < 32; i++) {
            String p = "secret-" + i;
            oldCts.add(infra.service.encrypt("payroll", p).ciphertext());
            plains.add(p);
        }
        infra.service.rotate(Duration.ofHours(24));

        long t0 = System.nanoTime();
        UpgradeResult up = infra.service.upgradeBatch(lease.leaseId(), oldCts);
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        log.info("批量升级 {} 份完成 target=v{}, 耗时={}ms", up.upgradedCount(),
                up.targetVersion(), elapsedMs);
        assertThat(up.upgradedCount()).isEqualTo(32);
        assertThat(up.items()).extracting(UpgradeItemResult::targetVersion)
                .containsOnly(2);
        // 顺序与入参一致；明文逐一一致
        for (int i = 0; i < 32; i++) {
            assertThat(up.items().get(i).sourceCiphertext()).isEqualTo(oldCts.get(i));
            SecretReadResult r = infra.service.read(lease.leaseId(), up.items().get(i).ciphertext());
            assertThat(r.plaintext()).isEqualTo(plains.get(i));
            assertThat(r.keyVersion()).isEqualTo(2);
        }

        // 任一项被篡改 -> 整批拒绝，且没有任何新密文吐出
        List<String> mixed = new java.util.ArrayList<>(oldCts.subList(0, 5));
        String bad = tamper(infra.service.encrypt("payroll", "later-current").ciphertext());
        // bad 是当前 v2 密文且已轮换后仍为 current；为制造“批次里一项坏”，直接对一份新 v2 密文篡改
        mixed.add(bad);
        expectUpgradeDeny(infra, lease.leaseId(), mixed,
                com.github.xingjianluo.secretsleaserotationjava.model.DenyReason.CIPHERTEXT_INVALID,
                "批次含篡改密文");
    }

    @Test
    void upgradeAtGraceBoundaryFollowsSameLeftOpenRuleAsRead() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1enc = infra.service.encrypt("payroll", "boundary");
        infra.service.rotate(Duration.ofHours(24));

        // 截止前一刻：可升级
        infra.advance(Duration.ofHours(23).plusMinutes(59));
        UpgradeResult ok = infra.service.upgrade(lease.leaseId(), v1enc.ciphertext());
        assertThat(ok.targetVersion()).isEqualTo(2);
        log.info("宽限截止前一刻升级成功 -> v{}", ok.targetVersion());

        // 再准备一份尚未升级的 v1 密文（用 v1 密钥手工构造：重新走一份初始数据更直观）
        // 到达截止时刻 T+24h：升级必须被明确拒绝
        TestInfra infra2 = TestInfra.newInfra();
        infra2.service.registerSubject("alice");
        LeaseIssueResult lease2 = infra2.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult v1b = infra2.service.encrypt("payroll", "boundary2");
        infra2.service.rotate(Duration.ofHours(24));
        infra2.advance(Duration.ofHours(24));
        assertThatThrownBy(() -> infra2.service.upgrade(lease2.leaseId(), v1b.ciphertext()))
                .isInstanceOf(KeyGraceExpiredException.class)
                .satisfies(e -> log.info("宽限截止时刻升级判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
    }

    @Test
    void tamperedCiphertextIsRejectedAndNoNewCiphertextReturned() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult enc = infra.service.encrypt("payroll", "authentic");
        infra.service.rotate(Duration.ofHours(24));
        String tampered = tamper(enc.ciphertext());

        expectUpgradeDeny(infra, lease.leaseId(), List.of(tampered),
                com.github.xingjianluo.secretsleaserotationjava.model.DenyReason.CIPHERTEXT_INVALID,
                "篡改密文升级");

        // 审计里必须是拒绝结论，且不含任何成功升级记录
        List<AuditEvent> ups = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_CIPHERTEXT).toList();
        assertThat(ups).isNotEmpty();
        assertThat(ups).allSatisfy(e -> assertThat(e.result()).startsWith("DENIED:"));
        log.info("篡改升级审计结果: {}", ups.get(ups.size() - 1).result());
    }

    @Test
    void upgradeLeaseGateIsEnforced() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.registerSubject("bob");
        EncryptResult enc = infra.service.encrypt("payroll", "gated");
        infra.service.rotate(Duration.ofHours(24));

        // 未知租约
        expectUpgradeDeny(infra, "no-such-lease", List.of(enc.ciphertext()),
                com.github.xingjianluo.secretsleaserotationjava.model.DenyReason.UNKNOWN_LEASE,
                "未知租约升级");

        // 作用域越权
        LeaseIssueResult hrLease = infra.service.issueLease("bob", "hr-files", Duration.ofMinutes(10));
        expectUpgradeDeny(infra, hrLease.leaseId(), List.of(enc.ciphertext()),
                com.github.xingjianluo.secretsleaserotationjava.model.DenyReason.SCOPE_MISMATCH,
                "越权升级");

        // 过期租约
        LeaseIssueResult expired = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        infra.advance(Duration.ofMinutes(10));
        expectUpgradeDeny(infra, expired.leaseId(), List.of(enc.ciphertext()),
                com.github.xingjianluo.secretsleaserotationjava.model.DenyReason.LEASE_EXPIRED,
                "过期租约升级");
    }

    @Test
    void purgePreconditionsAreEnforcedAndAudited() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        infra.service.encrypt("payroll", "x");
        infra.service.rotate(Duration.ofHours(24)); // v1 retired, v2 current

        // 当前版本不许清
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(2))
                .isInstanceOf(KeyVersionNotPurgeableException.class)
                .satisfies(e -> log.info("清理当前版本判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 宽限未到不许清
        infra.advance(Duration.ofHours(1));
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionNotPurgeableException.class)
                .satisfies(e -> log.info("宽限未到清理判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 不存在的版本不许清
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(99))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException.class);

        // 宽限到期：清理成功
        infra.advance(Duration.ofHours(23)); // T+24h
        PurgeResult purged = infra.service.purgeKeyVersion(1);
        log.info("清理成功 v{} at={}, graceDeadline={}", purged.version(),
                purged.purgedAt(), purged.graceDeadline());
        assertThat(purged.version()).isEqualTo(1);

        // 清理动作可追溯
        AuditEvent success = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.PURGE_KEY_VERSION && "SUCCESS".equals(e.result()))
                .findFirst().orElseThrow();
        assertThat(success.keyVersion()).isEqualTo(1);
        log.info("清理成功审计: result={}, detail={}", success.result(), success.detail());

        // 重复清理：明确告知已被移除（幂等视角下依旧是 KEY_VERSION_PURGED，而非当未知版本）
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(1))
                .isInstanceOf(KeyVersionPurgedException.class)
                .satisfies(e -> log.info("重复清理判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
    }

    @Test
    void readAndUpgradeAfterPurgeAreExplicitlyRejectedAsPurged() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        EncryptResult v1enc = infra.service.encrypt("payroll", "will-be-orphaned");
        infra.service.rotate(Duration.ofHours(24));
        infra.advance(Duration.ofHours(24));
        infra.service.purgeKeyVersion(1);

        // 清理后读取：KEY_VERSION_PURGED，不能拿当前 v2 顶替
        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), v1enc.ciphertext()))
                .isInstanceOf(KeyVersionPurgedException.class)
                .satisfies(e -> log.info("清理后读取判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 清理后升级：同样明确拒绝
        assertThatThrownBy(() -> infra.service.upgrade(lease.leaseId(), v1enc.ciphertext()))
                .isInstanceOf(KeyVersionPurgedException.class)
                .satisfies(e -> log.info("清理后升级判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 当前版本密文一切正常，证明不是全局故障
        EncryptResult fresh = infra.service.encrypt("payroll", "fresh");
        assertThat(infra.service.read(lease.leaseId(), fresh.ciphertext()).plaintext())
                .isEqualTo("fresh");
        log.info("当前版本 v{} 密文读取正常，清理只影响被移除版本", fresh.keyVersion());
    }
}
