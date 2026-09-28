package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 升级 × 轮换 × 清理并发的确定性时序测试。
 *
 * <p>用"门控"重加密（{@link GatedCrypto}）把升级固定卡在"已通过源版本校验/解密、
 * 正要产出目标版本新密文"这一点，随后由主线程同步完成轮换与清理，再放行升级，
 * 从而 100% 复现：升级进行中，其请求开始时锁定的目标当前版本被轮换退役并清理。
 *
 * <p>核心断言：这种时序下升级绝不会返回引用已不存在版本的密文——
 * 要么整批 {@code KEY_VERSION_PURGED}（或临界点 {@code KEY_VERSION_GRACE_EXPIRED}）
 * 明确拒绝、一条新密文都不吐；要么成功且返回密文可被同一租约立刻读回。
 */
class UpgradePurgeConcurrencyTests {

    private static final Logger log = LoggerFactory.getLogger(UpgradePurgeConcurrencyTests.class);

    /**
     * 场景一（清理先于升级提交）：升级卡在向 v2 重加密的中途，主线程轮换 v2→v3
     * （v2 宽限为 0）并立即清理 v2，再放行升级。
     *
     * <p>期望：升级以 {@code KEY_VERSION_PURGED} 被<b>整批明确拒绝</b>，不返回任何新密文；
     * 审计恰好一条 {@code DENIED:KEY_VERSION_PURGED} 且记录目标版本 v2；源密文本身未被改动。
     */
    @Test
    void upgradeInFlightWhenTargetIsRotatedAndPurgedIsRejectedWithNoGhostCiphertext() throws Exception {
        GatedCrypto crypto = new GatedCrypto(2);
        TestInfra infra = TestInfra.newInfra(crypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));

        // v1 源密文；轮换 v1→v2（v1 仍在 24h 宽限内，保证升级通过源版本校验、走到目标重加密）
        String v1Cipher = infra.service.encrypt("payroll", "ghost-version-secret").ciphertext();
        infra.service.rotate(Duration.ofHours(24));
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);
        log.info("[场景一-输入] 源密文=v1 密文，租约={}，升级开始时锁定目标=v2（当前版本）",
                lease.leaseId());

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<UpgradeResult> future = pool.submit(
                () -> infra.service.upgrade(lease.leaseId(), v1Cipher));

        // 等待升级进入"向 v2 重加密"的临界点
        crypto.awaitTargetEncryptEntered();
        log.info("[场景一-时序] 升级已解密源密文、正卡在向 v2 产出新密文；主线程开始轮换+清理");

        // 并发变更：v2→v3（v2 宽限 0），now==deadline 即宽限结束，可立即清理
        infra.service.rotate(Duration.ZERO);
        PurgeResult purge = infra.service.purgeKeyVersion(2);
        log.info("[场景一-时序] 轮换完成 v2→v3，v2 已清理 purgedAt={}（墓碑保留）", purge.purgedAt());
        assertThat(infra.keyStore.findVersion(2)).as("v2 密钥材料已移除").isEmpty();
        assertThat(infra.keyStore.findPurged(2)).as("v2 墓碑保留").isPresent();

        crypto.releaseTargetEncrypt();
        SecretLeaseException denial = awaitDenial(future);
        pool.shutdown();

        log.info("[场景一-判定] 升级被拒绝 reason={}，依据={}", denial.reason(), denial.getMessage());
        assertThat(denial).isInstanceOf(KeyVersionPurgedException.class);
        assertThat(denial.reason()).isEqualTo(DenyReason.KEY_VERSION_PURGED);
        assertThat(denial.getMessage()).contains("v2");

        // 恰好一条升级审计：被拒绝、原因明确、目标版本 v2；没有成功审计
        List<AuditEvent> upgradeAudits = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET).toList();
        assertThat(upgradeAudits).hasSize(1);
        AuditEvent audit = upgradeAudits.get(0);
        assertThat(audit.result()).isEqualTo("DENIED:" + DenyReason.KEY_VERSION_PURGED.name());
        assertThat(audit.keyVersion()).isEqualTo(2);
        assertThat(audit.leaseId()).isEqualTo(lease.leaseId());
        log.info("[场景一-审计] {} detail={}", audit.result(), audit.detail());
        long successAudits = upgradeAudits.stream().filter(e -> "SUCCESS".equals(e.result())).count();
        assertThat(successAudits).as("拒绝路径不得留下成功升级审计").isZero();

        // 源密文未被升级动作改动，仍可由同一租约读回（v1 宽限未过）
        var read = infra.service.read(lease.leaseId(), v1Cipher);
        assertThat(read.plaintext()).isEqualTo("ghost-version-secret");
        assertThat(read.scope()).isEqualTo("payroll");
        assertThat(infra.service.currentKeyVersion()).isEqualTo(3);
        log.info("[场景一-结论] 无幽灵密文吐出；源密文完好；当前版本=v3");
    }

    /**
     * 场景二（升级先提交，清理随后发生）：升级卡在向 v2 重加密中途时，
     * 主线程尝试清理 v2 被明确拒绝（它是当前版本）；放行升级，升级必须成功，
     * 返回的 v2 密文能被同一租约<b>立刻</b>读回、明文/作用域与升级前一致。
     *
     * <p>随后再轮换 v2→v3 并清理 v2：这是升级成功返回之后的正常版本生命周期，
     * 不与"返回时引用真实存在版本"的保证矛盾。升级与清理各自成功，结论完全对得上。
     */
    @Test
    void upgradeCommitsFirstThenPurgeHappensResultIsImmediatelyReadableAndStaysConsistent()
            throws Exception {
        GatedCrypto crypto = new GatedCrypto(2);
        TestInfra infra = TestInfra.newInfra(crypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        String v1Cipher = infra.service.encrypt("payroll", "commit-first-secret").ciphertext();
        infra.service.rotate(Duration.ofHours(24));
        log.info("[场景二-输入] 源=v1 密文，目标=v2（当前）；升级飞行中先尝试清理 v2");

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<UpgradeResult> future = pool.submit(
                () -> infra.service.upgrade(lease.leaseId(), v1Cipher));
        crypto.awaitTargetEncryptEntered();

        // 提交闸门之外、升级飞行期间：v2 仍是当前版本，清理被明确拒绝（412 NOT_PURGEABLE）
        assertThatThrownBy(() -> infra.service.purgeKeyVersion(2))
                .isInstanceOf(KeyVersionNotPurgeableException.class);
        log.info("[场景二-时序] 升级飞行中清理当前版本 v2 被前置条件明确拒绝");

        crypto.releaseTargetEncrypt();
        UpgradeResult up;
        try {
            up = future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw new AssertionError("此顺序下升级应当成功", e.getCause());
        }
        pool.shutdown();

        assertThat(up.targetVersion()).isEqualTo(2);
        assertThat(up.sourceVersion()).isEqualTo(1);
        log.info("[场景二-判定] 升级成功 v1->v2，立即用同一租约读回新密文");
        var readBack = infra.service.read(lease.leaseId(), up.ciphertext());
        assertThat(readBack.keyVersion()).isEqualTo(2);
        assertThat(readBack.plaintext()).isEqualTo("commit-first-secret");
        assertThat(readBack.scope()).isEqualTo("payroll");

        // 升级返回之后再轮换并清理 v2：已返回密文的版本此刻才退出历史舞台
        infra.service.rotate(Duration.ZERO);
        PurgeResult purged = infra.service.purgeKeyVersion(2);
        log.info("[场景二-时序] 升级成功返回后才轮换+清理 v2，purgedAt={}", purged.purgedAt());
        assertThat(infra.keyStore.findVersion(2)).isEmpty();
        assertThat(infra.service.currentKeyVersion()).isEqualTo(3);

        // 审计：恰好一条成功升级；清理 v2 成功一条；此前的非法清理另有一条拒绝
        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).isEqualTo(1);
        log.info("[场景二-结论] 升级成功时 v2 真实存在且可读；清理发生在返回之后，两动作结论一致");
    }

    /**
     * 场景三（批量原子 + 并行度不退化）：一批多条 v1 密文并行重加密到 v2，
     * 飞行中 v2 被轮换并清理。所有条目都已在并行重加密（观测到同时在飞数 >1），
     * 但提交闸门复核发现 v2 已被清理：整批 {@code KEY_VERSION_PURGED} 拒绝，
     * 一条新密文都不返回，成功升级审计为零。
     */
    @Test
    void batchFlyingWhenTargetPurgedIsWhollyRejectedAndStaysParallel() throws Exception {
        int size = 6;
        GatedCrypto crypto = new GatedCrypto(2);
        TestInfra infra = TestInfra.newInfra(crypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        List<String> batch = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            batch.add(infra.service.encrypt("payroll", "batch-secret-" + i).ciphertext());
        }
        infra.service.rotate(Duration.ofHours(24));
        log.info("[场景三-输入] 批量 size={} 全部 v1->v2，飞行中轮换并清理 v2", size);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<List<UpgradeResult>> future = pool.submit(
                () -> infra.service.upgradeBatch(lease.leaseId(), batch));

        // 等全部条目都进入 v2 重加密（CountDownLatch 只能数第一个，这里用忙等峰值达到 size）
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (crypto.targetEncryptHits() < size && System.nanoTime() < deadline) {
            Thread.sleep(2);
        }
        assertThat(crypto.targetEncryptHits())
                .as("6 个条目必须真正同时并行进入目标重加密").isEqualTo(size);
        log.info("[场景三-时序] {} 个条目全部在并行重加密 v2（未串行化），开始轮换+清理", size);

        infra.service.rotate(Duration.ZERO);
        infra.service.purgeKeyVersion(2);
        crypto.releaseTargetEncrypt();

        SecretLeaseException denial = awaitBatchDenial(future);
        pool.shutdown();
        log.info("[场景三-判定] 整批拒绝 reason={}", denial.reason());
        assertThat(denial).isInstanceOf(KeyVersionPurgedException.class);

        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).as("整批拒绝时不得有任何成功升级审计").isZero();
        long purgeDenials = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET
                        && "DENIED:KEY_VERSION_PURGED".equals(e.result()))
                .count();
        assertThat(purgeDenials).as("整批只记一条拒绝审计").isEqualTo(1);

        // 源密文全部完好，可由同一租约读回（v1 宽限内）
        for (int i = 0; i < size; i++) {
            assertThat(infra.service.read(lease.leaseId(), batch.get(i)).plaintext())
                    .isEqualTo("batch-secret-" + i);
        }
        log.info("[场景三-结论] 并行度保留(size={} 同时在飞)，整批零密文返回，源密文全部完好", size);
    }

    /**
     * 场景四（宽限临界恰在提交瞬间）：目标 v2 在升级飞行期间被轮换退役，
     * 其宽限期在升级提交那一刻恰好走到 {@code now == deadline}（左闭右开，视为结束）。
     * 没有清理发生，但提交闸门必须按 {@code KEY_VERSION_GRACE_EXPIRED} 整批拒绝——
     * 否则返回的 v2 密文立刻就不可读，同样违反"返回时可读"的保证。
     */
    @Test
    void targetGraceExpiresExactlyAtCommitIsRejectedNotReturned() throws Exception {
        GatedCrypto crypto = new GatedCrypto(2);
        TestInfra infra = TestInfra.newInfra(crypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        String v1Cipher = infra.service.encrypt("payroll", "grace-edge-secret").ciphertext();
        // v1->v2：v1 给 48h 宽限（保证源校验通过）；随后在飞行中让 v2 以 24h 宽限退役
        infra.service.rotate(Duration.ofHours(48));
        log.info("[场景四-输入] 源=v1，目标=v2；飞行中把 v2 退役并把时钟推到其宽限截止时刻");

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<UpgradeResult> future = pool.submit(
                () -> infra.service.upgrade(lease.leaseId(), v1Cipher));
        crypto.awaitTargetEncryptEntered();

        // v2 退役（宽限 24h），v3 成为当前；时钟推进到 v2 的 graceDeadline（now==deadline）
        infra.service.rotate(Duration.ofHours(24));
        infra.advance(Duration.ofHours(24));
        log.info("[场景四-时序] v2 已退役且 now==graceDeadline；放行升级提交");
        crypto.releaseTargetEncrypt();

        SecretLeaseException denial = awaitDenial(future);
        pool.shutdown();
        log.info("[场景四-判定] reason={} 依据={}", denial.reason(), denial.getMessage());
        assertThat(denial).isInstanceOf(KeyGraceExpiredException.class);
        assertThat(denial.reason()).isEqualTo(DenyReason.KEY_VERSION_GRACE_EXPIRED);
        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).isZero();
        log.info("[场景四-结论] 提交瞬间宽限结束也被明确拒绝，无返回后立刻不可读的密文");
    }

    /**
     * 场景五（只有轮换、没有清理）：目标 v2 在飞行中仅被轮换退役（仍在宽限内）。
     * 这种既有允许的顺序必须保持：升级成功、新密文引用 v2，且同一租约立刻可读、
     * 明文/作用域不变——提交闸门不会把"仅轮换"误判为冲突或拒绝。
     */
    @Test
    void targetOnlyRotatedStillInGraceUpgradeSucceedsAndReadsBack() throws Exception {
        GatedCrypto crypto = new GatedCrypto(2);
        TestInfra infra = TestInfra.newInfra(crypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        String v1Cipher = infra.service.encrypt("payroll", "rotate-only-secret").ciphertext();
        infra.service.rotate(Duration.ofHours(48));
        log.info("[场景五-输入] 源=v1，目标=v2；飞行中仅轮换 v2->v3（v2 宽限 24h，不清理）");

        ExecutorService pool = Executors.newSingleThreadExecutor();
        Future<UpgradeResult> future = pool.submit(
                () -> infra.service.upgrade(lease.leaseId(), v1Cipher));
        crypto.awaitTargetEncryptEntered();
        infra.service.rotate(Duration.ofHours(24));
        assertThat(infra.keyStore.findVersion(2)).as("v2 仅退役、未清理，材料仍在").isPresent();
        crypto.releaseTargetEncrypt();

        UpgradeResult up;
        try {
            up = future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw new AssertionError("仅轮换且目标仍在宽限内时升级应成功", e.getCause());
        }
        pool.shutdown();
        assertThat(up.targetVersion()).isEqualTo(2);
        var readBack = infra.service.read(lease.leaseId(), up.ciphertext());
        assertThat(readBack.keyVersion()).isEqualTo(2);
        assertThat(readBack.plaintext()).isEqualTo("rotate-only-secret");
        assertThat(readBack.scope()).isEqualTo("payroll");
        assertThat(infra.service.currentKeyVersion()).isEqualTo(3);
        log.info("[场景五-结论] 仅轮换不清理：升级成功，v2 返回时仍存活可读，未被误拒");
    }

    /** 等待批量升级任务结束并取出其被拒绝异常；若竟然成功返回则直接失败。 */
    @SuppressWarnings("unchecked")
    private static SecretLeaseException awaitBatchDenial(Future<List<UpgradeResult>> future)
            throws InterruptedException {
        try {
            List<UpgradeResult> leaked = future.get(10, TimeUnit.SECONDS);
            throw new AssertionError("整批升级不应返回任何新密文，却返回了 " + leaked.size() + " 条");
        } catch (ExecutionException ee) {
            assertThat(ee.getCause()).isInstanceOf(SecretLeaseException.class);
            return (SecretLeaseException) ee.getCause();
        } catch (java.util.concurrent.TimeoutException e) {
            throw new AssertionError("批量升级任务超时未结束", e);
        }
    }

    /** 等待升级任务结束并取出其被拒绝异常；若它竟然成功返回则直接失败（幽灵密文）。 */
    private static SecretLeaseException awaitDenial(Future<UpgradeResult> future)
            throws InterruptedException {
        try {
            UpgradeResult leaked = future.get(10, TimeUnit.SECONDS);
            throw new AssertionError("升级不应返回任何新密文，却返回了 targetVersion=v"
                    + leaked.targetVersion() + " 的密文（引用已不存在/不可读版本）");
        } catch (ExecutionException ee) {
            assertThat(ee.getCause()).isInstanceOf(SecretLeaseException.class);
            return (SecretLeaseException) ee.getCause();
        } catch (java.util.concurrent.TimeoutException e) {
            throw new AssertionError("升级任务超时未结束", e);
        }
    }

    /**
     * 门控加密：所有用 {@code gatedTargetVersion} 做的重加密都会在真正加密前阻塞，
     * 直到测试显式放行；其余版本的加密/解密完全不受影响。
     * 用 {@link #hits} 可观测有多少条目同时卡在目标重加密（证明批量并行）。
     */
    static final class GatedCrypto extends LocalCryptoService {
        private final int gatedTargetVersion;
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicInteger hits = new AtomicInteger();

        GatedCrypto(int gatedTargetVersion) {
            this.gatedTargetVersion = gatedTargetVersion;
        }

        @Override
        public String encrypt(int version, String scope, byte[] key, String plaintext) {
            if (version == gatedTargetVersion) {
                hits.incrementAndGet();
                entered.countDown();
                try {
                    assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("门控等待被中断", e);
                }
            }
            return super.encrypt(version, scope, key, plaintext);
        }

        void awaitTargetEncryptEntered() throws InterruptedException {
            assertThat(entered.await(10, TimeUnit.SECONDS))
                    .as("升级必须进入目标版本重加密").isTrue();
        }

        int targetEncryptHits() {
            return hits.get();
        }

        void releaseTargetEncrypt() {
            release.countDown();
        }
    }
}
