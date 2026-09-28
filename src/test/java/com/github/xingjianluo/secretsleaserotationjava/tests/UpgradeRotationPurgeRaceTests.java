package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UpgradeTargetSupersededException;
import com.github.xingjianluo.secretsleaserotationjava.model.Action;
import com.github.xingjianluo.secretsleaserotationjava.model.AuditEvent;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.PurgeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 升级进行中同时发生轮换/清理的确定性并发测试。
 *
 * <p>时序用"只在指定版本重加密时阻塞"的慢速 crypto + 同步点固定下来，不依赖真实 sleep 抖动：
 * 升级线程在"已解密旧密文、正用锁定的目标版本重加密"处被闸门挡住，测试线程在此期间
 * 完成轮换（v2 -> v3）并把宽限期为 0 的 v2 清理掉，再放行升级线程完成提交。
 *
 * <p>修复前：升级返回的新密文引用 v2，而 v2 已被清理，随后同一租约立刻读回得到
 * {@code KEY_VERSION_PURGED}（升级返回了引用不存在版本的密文）。
 * 修复后：升级在提交点重新校验目标版本，整批明确拒绝（KEY_VERSION_PURGED），
 * 一条新密文都不吐；重试时落到真实存在的当前版本。
 */
class UpgradeRotationPurgeRaceTests {

    private static final Logger log = LoggerFactory.getLogger(UpgradeRotationPurgeRaceTests.class);

    /**
     * 核心场景：v1 -> v2 的升级进行中，v2 被轮换为 v3 且被清理。
     * 升级必须整批明确拒绝，拒绝原因能看出是"目标版本已被移除"，且没有成功审计、没有结果外泄。
     */
    @Test
    void upgradeInFlightWhileTargetRotatedAndPurgedIsWholesaleRejectedAsPurged() throws Exception {
        ReentrantLock gate = new ReentrantLock();
        gate.lock(); // v2 重加密会阻塞在此，直到测试放行
        AtomicReference<String> readbackError = new AtomicReference<>();
        LocalCryptoService gatingCrypto = new LocalCryptoService() {
            @Override
            public String encrypt(int version, String scope, byte[] key, String plaintext) {
                if (version == 2) {
                    // 只挡住升级"用 v2 重加密"这一步：此时旧密文已解密，目标版本已锁定
                    gate.lock();
                    gate.unlock();
                }
                return super.encrypt(version, scope, key, plaintext);
            }
        };
        TestInfra infra = TestInfra.newInfra(gatingCrypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        EncryptResult v1 = infra.service.encrypt("payroll", "race-secret");

        // v1 进入宽限期（24h，保证源版本此刻可解），当前版本变为 v2（升级锁定的目标）
        infra.service.rotate(Duration.ofHours(24));
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);

        ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "in-flight-upgrader");
            t.setDaemon(true);
            return t;
        });
        CountDownLatch entered = new CountDownLatch(1);
        Future<?> upgradeFuture = pool.submit(() -> {
            entered.countDown();
            try {
                UpgradeResult up = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
                // 若修复前错误地返回了结果，立刻用同一租约读回验证它引用的版本是否还存在
                log.error("[竞争-清理目标] 升级竟然返回了新密文: source=v{}, target=v{}",
                        up.sourceVersion(), up.targetVersion());
                try {
                    SecretReadResult read = infra.service.read(lease.leaseId(), up.ciphertext());
                    if (!"race-secret".equals(read.plaintext()) || read.keyVersion() != up.targetVersion()) {
                        readbackError.set("读回内容不一致");
                    }
                } catch (KeyVersionPurgedException e) {
                    readbackError.set("升级结果引用的版本已被清理: " + e.getMessage());
                }
            } catch (SecretLeaseException e) {
                log.info("[竞争-清理目标] 升级被明确拒绝: 判定={}, 依据={}", e.reason(), e.getMessage());
            }
        });
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        // 等升级线程进入 v2 重加密闸门
        Thread.sleep(200);

        // 升级进行中：v2 退役（零宽限）-> v3 成为当前，随后立即把 v2 清理掉
        infra.service.rotate(Duration.ZERO);
        infra.advance(Duration.ofMillis(1)); // 越过 v2 宽限截止点
        PurgeResult purge = infra.service.purgeKeyVersion(2);
        log.info("[竞争-清理目标] 升级进行中完成: 当前版本=v3, v2 已清理 purgedAt={}", purge.purgedAt());
        assertThat(infra.keyStore.findVersion(2)).isEmpty();
        assertThat(infra.keyStore.findPurged(2)).isPresent();

        gate.unlock(); // 放行升级线程完成其重加密并走到提交点
        upgradeFuture.get(10, TimeUnit.SECONDS);
        pool.shutdown();

        // 升级绝不能返回引用已清理 v2 的密文：不能有成功审计，也不能读回报 PURGED
        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).as("目标版本已被清理时不得有成功升级，不能吐出任何新密文").isZero();
        assertThat(readbackError.get())
                .as("绝不允许返回引用已清理版本、随后读回才暴露问题的密文")
                .isNull();

        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET
                        && e.result().equals("DENIED:" + DenyReason.KEY_VERSION_PURGED.name()))
                .findFirst().orElseThrow(() -> new AssertionError("缺少 KEY_VERSION_PURGED 的升级拒绝审计"));
        assertThat(denied.keyVersion()).isEqualTo(2);
        assertThat(denied.detail()).contains("2");
        log.info("[竞争-清理目标] 拒绝审计: result={}, detail={}", denied.result(), denied.detail());

        // 状态明确一致：重试升级必须落到真实存在的当前版本 v3，并能立即读回
        UpgradeResult retried = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
        assertThat(retried.sourceVersion()).isEqualTo(1);
        assertThat(retried.targetVersion()).isEqualTo(3);
        SecretReadResult read = infra.service.read(lease.leaseId(), retried.ciphertext());
        assertThat(read.keyVersion()).isEqualTo(3);
        assertThat(read.plaintext()).isEqualTo("race-secret");
        assertThat(read.scope()).isEqualTo("payroll");
        log.info("[竞争-清理目标] 重试升级 -> v3 并立即读回成功: plaintext={}, scope={}",
                read.plaintext(), read.scope());
    }

    /**
     * 目标版本在升级期间仅被轮换取代（尚未清理）：升级同样整批拒绝，
     * 原因是 UPGRADE_TARGET_SUPERSEDED，不悄悄改用 v3 顶替，也不返回 v2 密文。
     */
    @Test
    void upgradeInFlightWhileTargetRotatedIsRejectedAsSupersededNotSilentlyRetargeted() throws Exception {
        ReentrantLock gate = new ReentrantLock();
        gate.lock();
        LocalCryptoService gatingCrypto = new LocalCryptoService() {
            @Override
            public String encrypt(int version, String scope, byte[] key, String plaintext) {
                if (version == 2) {
                    gate.lock();
                    gate.unlock();
                }
                return super.encrypt(version, scope, key, plaintext);
            }
        };
        TestInfra infra = TestInfra.newInfra(gatingCrypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        EncryptResult v1 = infra.service.encrypt("payroll", "superseded-secret");
        infra.service.rotate(Duration.ofHours(24)); // 当前 v2，源 v1 仍在宽限

        ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "in-flight-upgrader");
            t.setDaemon(true);
            return t;
        });
        CountDownLatch entered = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Future<?> f = pool.submit(() -> {
            entered.countDown();
            try {
                UpgradeResult up = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
                failure.set(new AssertionError("不应返回引用已退役 v2 的密文，实际 target=v"
                        + up.targetVersion()));
            } catch (UpgradeTargetSupersededException e) {
                log.info("[竞争-仅轮换] 升级被明确拒绝: 判定={}, 依据={}", e.reason(), e.getMessage());
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        Thread.sleep(200);

        // 只轮换，不清理：v2 退役（宽限 24h，仍存活），v3 成为当前
        infra.service.rotate(Duration.ofHours(24));
        assertThat(infra.keyStore.findVersion(2)).isPresent();
        assertThat(infra.service.currentKeyVersion()).isEqualTo(3);
        log.info("[竞争-仅轮换] 升级进行中完成轮换: v2 退役但存活，当前=v3");

        gate.unlock();
        f.get(10, TimeUnit.SECONDS);
        pool.shutdown();

        assertThat(failure.get()).isNull();
        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).as("目标版本已被取代时不得返回任何新密文").isZero();
        AuditEvent denied = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET
                        && e.result().equals("DENIED:" + DenyReason.UPGRADE_TARGET_SUPERSEDED.name()))
                .findFirst().orElseThrow(() -> new AssertionError("缺少 SUPERSEDED 拒绝审计"));
        assertThat(denied.keyVersion()).isEqualTo(2);
        log.info("[竞争-仅轮换] 拒绝审计: result={}, detail={}", denied.result(), denied.detail());

        // v2 未被清掉，重新升级应照常成功，落到当前 v3，不会出现"各自报成功却对不上"
        UpgradeResult retried = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
        assertThat(retried.targetVersion()).isEqualTo(3);
        SecretReadResult read = infra.service.read(lease.leaseId(), retried.ciphertext());
        assertThat(read.plaintext()).isEqualTo("superseded-secret");
        assertThat(read.keyVersion()).isEqualTo(3);
        log.info("[竞争-仅轮换] 重试升级 -> v3，读回明文一致");
    }

    /**
     * 批量升级在并行重加密期间目标版本被轮换并清理：整批拒绝，绝不返回部分新密文。
     * 所有条目共用同一个闸门（峰值仍并行），放行后统一在提交点被拒。
     */
    @Test
    void batchUpgradeInFlightWhileTargetPurgedIsWholesaleRejectedNoPartialResults() throws Exception {
        int size = 8;
        ReentrantLock gate = new ReentrantLock();
        gate.lock();
        CountDownLatch blocked = new CountDownLatch(size);
        LocalCryptoService gatingCrypto = new LocalCryptoService() {
            @Override
            public String encrypt(int version, String scope, byte[] key, String plaintext) {
                if (version == 2) {
                    blocked.countDown();
                    gate.lock();
                    gate.unlock();
                }
                return super.encrypt(version, scope, key, plaintext);
            }
        };
        TestInfra infra = TestInfra.newInfra(gatingCrypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        List<String> batch = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            batch.add(infra.service.encrypt("payroll", "batch-" + i).ciphertext());
        }
        infra.service.rotate(Duration.ofHours(24)); // 当前 v2

        ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "in-flight-batch-upgrader");
            t.setDaemon(true);
            return t;
        });
        CountDownLatch entered = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Future<?> f = pool.submit(() -> {
            entered.countDown();
            try {
                List<UpgradeResult> out = infra.service.upgradeBatch(lease.leaseId(), batch);
                failure.set(new AssertionError("批量升级不应成功，却返回 " + out.size() + " 条新密文"));
            } catch (KeyVersionPurgedException e) {
                log.info("[批量竞争] 整批被明确拒绝: 判定={}, 依据={}", e.reason(), e.getMessage());
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        // 等全部条目都已并行进入重加密闸门（证明并行度保留，再统一制造轮换+清理）
        assertThat(blocked.await(10, TimeUnit.SECONDS)).isTrue();
        infra.service.rotate(Duration.ZERO);
        infra.advance(Duration.ofMillis(1));
        infra.service.purgeKeyVersion(2);
        log.info("[批量竞争] {} 条升级全部在飞时，v2 被轮换并清理", size);

        gate.unlock();
        f.get(10, TimeUnit.SECONDS);
        pool.shutdown();

        assertThat(failure.get()).isNull();
        long successUpgrades = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successUpgrades).as("批量竞争下不得产生任何成功升级记录").isZero();
    }

    /**
     * 压力场景：多个升级线程持续工作，另一个线程反复"轮换 + 越过宽限 + 清理前一版本"。
     * 终态不变式（不依赖线程调度）：对每一条成功升级审计，其目标版本要么仍存活，
     * 要么其墓碑的 purgedAt 严格晚于升级提交时刻——即升级提交时该版本必然真实存在。
     */
    @Test
    void stressUpgradesInterleavedWithRotateAndPurgeNeverCommitToAnAlreadyPurgedVersion() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(10_000));
        // 始终持有一份"当前版本"密文供升级线程取用（refresher 在每次轮换后更新）
        AtomicReference<String> latest =
                new AtomicReference<>(infra.service.encrypt("payroll", "stress-secret").ciphertext());

        int rounds = 15;
        int upgraders = 4;
        ExecutorService pool = Executors.newFixedThreadPool(upgraders + 2);
        CountDownLatch start = new CountDownLatch(1);
        LinkedBlockingQueue<UpgradeResult> successes = new LinkedBlockingQueue<>();

        for (int i = 0; i < upgraders; i++) {
            pool.submit(() -> {
                await(start);
                for (int k = 0; k < 30; k++) {
                    try {
                        UpgradeResult up = infra.service.upgrade(lease.leaseId(), latest.get());
                        successes.add(up);
                        // 能成功则其目标版本此刻必须存活并能立即读回
                        SecretReadResult read = infra.service.read(lease.leaseId(), up.ciphertext());
                        assertThat(read.plaintext()).isEqualTo("stress-secret");
                        assertThat(read.keyVersion()).isEqualTo(up.targetVersion());
                    } catch (SecretLeaseException e) {
                        // PURGED / SUPERSEDED / GRACE_EXPIRED 等明确拒绝都是允许结论
                        log.debug("压力升级被明确拒绝: {}", e.reason());
                    }
                    // 留出轮换/清理推进窗口：提交点只在最后短暂持锁，这里模拟调用方处理结果的间隙
                    try {
                        Thread.sleep(2);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            });
        }
        Future<?> mutator = pool.submit(() -> {
            await(start);
            for (int r = 0; r < rounds; r++) {
                try {
                    infra.service.rotate(Duration.ZERO);
                    infra.advance(Duration.ofMillis(1));
                    int cur = infra.service.currentKeyVersion();
                    latest.set(infra.service.encrypt("payroll", "stress-secret").ciphertext());
                    int victim = cur - 1;
                    if (infra.keyStore.findVersion(victim).isPresent()) {
                        infra.service.purgeKeyVersion(victim);
                    }
                } catch (SecretLeaseException e) {
                    log.debug("压力轮换/清理被明确拒绝: {}", e.reason());
                }
            }
        });
        start.countDown();
        mutator.get(30, TimeUnit.SECONDS);
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        log.info("[压力] 成功升级={}（拒绝为明确结论），最终当前版本=v{}",
                successes.size(), infra.service.currentKeyVersion());

        // 终态不变式：成功升级的提交时刻，目标版本必然还真实存在
        for (AuditEvent e : infra.auditEvents()) {
            if (e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result())) {
                int v = e.keyVersion();
                if (infra.keyStore.findVersion(v).isEmpty()) {
                    var tomb = infra.keyStore.findPurged(v)
                            .orElseThrow(() -> new AssertionError(
                                    "成功升级 v" + v + " 但该版本既不存活也无墓碑"));
                    assertThat(tomb.purgedAt())
                            .as("升级提交(%s) 时 v%d 必须仍存在，但它在 %s 已被清理", e.at(), v, tomb.purgedAt())
                            .isAfter(e.at());
                }
            }
        }
    }

    /**
     * 提交点审计失败也要 fail-closed：目标版本此刻仍是当前版本、条目全部算完，
     * 但成功审计写不进去时，升级必须抛出 AUDIT_FAILURE、不返回新密文、不留 SUCCESS 记录。
     */
    @Test
    void auditFailureAtCommitPointDeniesUpgradeAndReturnsNoCiphertext() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        EncryptResult v1 = infra.service.encrypt("payroll", "audit-at-commit");
        infra.service.rotate(Duration.ofHours(24));

        // 前面的读取/校验审计都正常，只让"升级成功审计"这一次写入失败
        infra.auditSink.failNext();
        long successBefore = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> infra.service.upgrade(lease.leaseId(), v1.ciphertext()))
                .isInstanceOf(com.github.xingjianluo.secretsleaserotationjava.exception
                        .AuditFailureException.class)
                .satisfies(e -> log.info("[提交点审计失败] 判定={}",
                        ((SecretLeaseException) e).reason()));

        long successAfter = infra.auditEvents().stream()
                .filter(e -> e.action() == Action.UPGRADE_SECRET && "SUCCESS".equals(e.result()))
                .count();
        assertThat(successAfter).as("审计失败时不得留下成功升级记录").isEqualTo(successBefore);

        // 审计恢复后重试应成功
        UpgradeResult retried = infra.service.upgrade(lease.leaseId(), v1.ciphertext());
        assertThat(retried.targetVersion()).isEqualTo(2);
        assertThat(infra.service.read(lease.leaseId(), retried.ciphertext()).plaintext())
                .isEqualTo("audit-at-commit");
        log.info("[提交点审计失败] 审计恢复后重试升级 -> v2 成功");
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
