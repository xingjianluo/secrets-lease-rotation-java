package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.crypto.Envelope;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseRevokedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 密文升级：把旧版本密文重新加密为当前版本。
 * 覆盖宽限期内升级、宽限临界点、已是当前版本、被篡改/不可解拒绝、租约拒绝、
 * 批量原子性（一条坏全批拒、绝不吐出部分新密文）、以及升级结果可被同一租约读取验证。
 */
class UpgradeTests {

    private static final Logger log = LoggerFactory.getLogger(UpgradeTests.class);

    /** 篡改密文体：保留版本/作用域前缀，翻转载荷字节，使 GCM 完整性校验失败。 */
    private static String tamper(String ciphertext) {
        String[] parts = ciphertext.split(":", 3);
        byte[] body = Base64.getDecoder().decode(parts[2]);
        body[body.length - 1] ^= (byte) 0xFF;
        return parts[0] + ":" + parts[1] + ":" + Base64.getEncoder().encodeToString(body);
    }

    private static int versionOf(String ciphertext) {
        return Integer.parseInt(ciphertext.substring(1, ciphertext.indexOf(':')));
    }

    @Test
    void upgradeWithinGraceProducesCurrentVersionWithSamePlaintextAndScope() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult enc = infra.service.encrypt("payroll", "salary-4242");
        log.info("[宽限期内升级] 输入: 密文版本=v{}, scope=payroll, plaintext=salary-4242", enc.keyVersion());

        RotateResult rot = infra.service.rotate(Duration.ofHours(24));
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);

        // 宽限期内（T+23h）升级 v1 -> v2
        infra.advance(Duration.ofHours(23));
        UpgradeResult up = infra.service.upgrade(lease.leaseId(), enc.ciphertext());
        log.info("[宽限期内升级] 判定: source=v{}, target=v{}", up.sourceVersion(), up.targetVersion());
        assertThat(up.sourceVersion()).isEqualTo(1);
        assertThat(up.targetVersion()).isEqualTo(2);
        assertThat(versionOf(up.ciphertext())).isEqualTo(2);
        Envelope parsed = new LocalCryptoService().parse(up.ciphertext());
        assertThat(parsed.scope()).isEqualTo("payroll");

        // 新密文用同一租约读取：明文一致、作用域一致、落在当前版本 v2
        SecretReadResult read = infra.service.read(lease.leaseId(), up.ciphertext());
        assertThat(read.plaintext()).isEqualTo("salary-4242");
        assertThat(read.scope()).isEqualTo("payroll");
        assertThat(read.keyVersion()).isEqualTo(2);
        log.info("[宽限期内升级] 新密文同一租约读取: plaintext={}, scope={}, version=v{}",
                read.plaintext(), read.scope(), read.keyVersion());

        // 原旧密文在宽限期内依然可读（升级不破坏旧密文）
        assertThat(infra.service.read(lease.leaseId(), enc.ciphertext()).plaintext())
                .isEqualTo("salary-4242");
    }

    @Test
    void upgradeIsRejectedAtGraceDeadlineBoundary() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult enc = infra.service.encrypt("payroll", "boundary-secret");
        infra.service.rotate(Duration.ofHours(24));

        // 截止前一刻可升级
        infra.advance(Duration.ofHours(24).minusMinutes(1));
        UpgradeResult up = infra.service.upgrade(lease.leaseId(), enc.ciphertext());
        assertThat(up.targetVersion()).isEqualTo(2);
        log.info("[宽限临界点] T+23h59m 升级成功 -> v{}", up.targetVersion());

        // 再取一份原始 v1 密文（上面那份已升级不影响原密文），推进到截止时刻 T+24h
        infra.advance(Duration.ofMinutes(1));
        assertThatThrownBy(() -> infra.service.upgrade(lease.leaseId(), enc.ciphertext()))
                .isInstanceOf(KeyGraceExpiredException.class)
                .satisfies(e -> log.info("[宽限临界点] T+24h 升级判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
    }

    @Test
    void upgradeAlreadyCurrentCiphertextIsIdempotent() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        EncryptResult enc = infra.service.encrypt("payroll", "fresh");
        assertThat(enc.keyVersion()).isEqualTo(1);

        UpgradeResult up = infra.service.upgrade(lease.leaseId(), enc.ciphertext());
        log.info("[已是当前版本] source=v{}, target=v{}（重新加密，明文作用域不变）",
                up.sourceVersion(), up.targetVersion());
        assertThat(up.sourceVersion()).isEqualTo(1);
        assertThat(up.targetVersion()).isEqualTo(1);
        assertThat(infra.service.read(lease.leaseId(), up.ciphertext()).plaintext())
                .isEqualTo("fresh");
    }

    @Test
    void upgradeTamperedCiphertextIsRejectedAndYieldsNothing() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        EncryptResult enc = infra.service.encrypt("payroll", "do-not-upgrade-if-tampered");
        infra.service.rotate(Duration.ofHours(24));
        String bad = tamper(enc.ciphertext());
        log.info("[篡改密文] 输入密文头={}（已翻转载荷末字节）", bad.substring(0, 18));

        long auditBefore = infra.auditEvents().size();
        assertThatThrownBy(() -> infra.service.upgrade(lease.leaseId(), bad))
                .isInstanceOf(UnknownKeyVersionException.class)
                .satisfies(e -> log.info("[篡改密文] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 被拒：有一条 DENIED 审计，且没有任何成功升级记录
        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(denied.result()).isEqualTo("DENIED:UNKNOWN_KEY_VERSION");
        assertThat(infra.auditEvents()).hasSize((int) auditBefore + 1);
        boolean leaked = infra.auditEvents().stream()
                .anyMatch(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()));
        assertThat(leaked).as("篡改时不得有成功升级记录").isFalse();
    }

    @Test
    void upgradeWithInvalidLeaseIsRejectedWithoutNewCiphertext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.registerSubject("bob");
        LeaseIssueResult aliceLease =
                infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        LeaseIssueResult bobLease =
                infra.service.issueLease("bob", "hr-files", Duration.ofMinutes(10));
        EncryptResult enc = infra.service.encrypt("payroll", "cross-scope");

        // 未知租约
        assertThatThrownBy(() -> infra.service.upgrade("missing-lease", enc.ciphertext()))
                .isInstanceOf(UnknownLeaseException.class)
                .satisfies(e -> log.info("[升级-未知租约] 判定={}", ((SecretLeaseException) e).reason()));

        // 越权租约（scope 不匹配）
        assertThatThrownBy(() -> infra.service.upgrade(bobLease.leaseId(), enc.ciphertext()))
                .isInstanceOf(ScopeMismatchException.class)
                .satisfies(e -> log.info("[升级-越权] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 已撤销租约
        infra.service.revoke(aliceLease.leaseId());
        assertThatThrownBy(() -> infra.service.upgrade(aliceLease.leaseId(), enc.ciphertext()))
                .isInstanceOf(LeaseRevokedException.class)
                .satisfies(e -> log.info("[升级-撤销] 判定={}", ((SecretLeaseException) e).reason()));
    }

    @Test
    void batchUpgradeIsAtomicOneBadItemRejectsAllAndReleasesNoCiphertext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(100));
        List<String> secrets = List.of("s1", "s2", "s3");
        List<String> oldCiphertexts = secrets.stream()
                .map(s -> infra.service.encrypt("payroll", s).ciphertext()).toList();
        infra.service.rotate(Duration.ofHours(24));

        // 中间一条被篡改
        List<String> batch = new ArrayList<>(oldCiphertexts);
        batch.set(1, tamper(batch.get(1)));
        log.info("[批量原子] batchSize=3，第 1 条被篡改，期望整批拒绝、无任何新密文返回");

        List<UpgradeResult>[] holder = new List[1];
        assertThatThrownBy(() -> holder[0] = infra.service.upgradeBatch(lease.leaseId(), batch))
                .isInstanceOf(UnknownKeyVersionException.class)
                .satisfies(e -> log.info("[批量原子] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
        assertThat(holder[0]).as("整批拒绝时调用方不得拿到结果列表").isNull();

        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(denied.detail()).contains("失败位置=1");
        log.info("[批量原子] 拒绝审计 detail={}", denied.detail());

        // 全部好的一批应成功，顺序与输入一致，明文作用域一致，全部落到当前版本
        List<UpgradeResult> ok = infra.service.upgradeBatch(lease.leaseId(), oldCiphertexts);
        assertThat(ok).hasSize(3);
        for (int i = 0; i < 3; i++) {
            UpgradeResult u = ok.get(i);
            assertThat(u.targetVersion()).isEqualTo(2);
            SecretReadResult r = infra.service.read(lease.leaseId(), u.ciphertext());
            assertThat(r.plaintext()).isEqualTo(secrets.get(i));
            assertThat(r.scope()).isEqualTo("payroll");
            assertThat(r.keyVersion()).isEqualTo(2);
        }
        log.info("[批量原子] 全好批次升级成功并逐条读回校验: {} 条", ok.size());
    }

    @Test
    void emptyBatchIsRejectedAsBadRequest() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        assertThatThrownBy(() -> infra.service.upgradeBatch(lease.leaseId(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        log.info("[空批次] 按非法参数拒绝");
    }

    @Test
    void readingTamperedCiphertextIsExplicitlyDeniedAndAudited() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        EncryptResult enc = infra.service.encrypt("payroll", "integrity");
        String bad = tamper(enc.ciphertext());
        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), bad))
                .isInstanceOf(UnknownKeyVersionException.class)
                .satisfies(e -> log.info("[读取篡改] 判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.READ_SECRET && e.result().startsWith("DENIED"))
                .findFirst().orElseThrow();
        assertThat(denied.result()).isEqualTo("DENIED:UNKNOWN_KEY_VERSION");
        assertThat(denied.keyVersion()).isEqualTo(1);
    }
}
