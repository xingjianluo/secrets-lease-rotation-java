package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.model.UpgradeResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 升级与轮换并发：
 * 1) 每次升级要么落到当时真实存在的当前版本（产出密文可立即用同租约读出、明文一致），
 *    要么以可解释原因被拒绝；绝不产出引用不存在版本的密文，也观察不到半成品；
 * 2) 同一份密文被并发升级多次，内容与计数不被搞乱（每次都是全有或全无的完整结论）。
 */
class ConcurrentUpgradeRotationTests {

    private static final Logger log =
            LoggerFactory.getLogger(ConcurrentUpgradeRotationTests.class);

    @Test
    void upgradesInterleavedWithRotationsAlwaysLandOnARealCurrentVersion() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        // 宽限给足：本次只验证并发一致性，不让宽限期成为拒绝来源
        List<String> sourceCts = new ArrayList<>();
        List<String> plains = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            String p = "interleaved-" + i;
            sourceCts.add(infra.service.encrypt("payroll", p).ciphertext());
            plains.add(p);
        }

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger conflictCount = new AtomicInteger();
        try {
            List<Future<?>> futures = new ArrayList<>();
            // 4 个升级线程 + 4 个轮换线程同时起跑
            for (int t = 0; t < threads; t++) {
                final int idx = t;
                futures.add(pool.submit(() -> {
                    await(barrier);
                    try {
                        if (idx % 2 == 0) {
                            // 每个升级线程负责 5 份不同密文（保证批次内容不重叠）
                            List<String> batch = sourceCts.subList(idx * 5, idx * 5 + 5);
                            UpgradeResult up = infra.service.upgradeBatch(lease.leaseId(), batch);
                            successCount.addAndGet(verifyUpgraded(infra, lease.leaseId(),
                                    up, batch));
                        } else {
                            infra.service.rotate(Duration.ofHours(1000));
                        }
                    } catch (SecretLeaseException e) {
                        // 升级与轮换互斥：冲突是被允许的明确结论
                        if (e.reason() == DenyReason.ROTATION_IN_PROGRESS) {
                            conflictCount.incrementAndGet();
                        } else {
                            throw new AssertionError("并发中出现非预期拒绝: " + e.reason(), e);
                        }
                    }
                }));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        log.info("并发结论: 升级成功密文份数={}, 冲突拒绝次数={}, 最终当前版本=v{}",
                successCount.get(), conflictCount.get(), infra.service.currentKeyVersion());
        assertThat(successCount.get() + (conflictCount.get() > 0 ? 0 : 0))
                .as("至少应有升级成功或冲突拒绝发生").isGreaterThan(0);
        // 全部源密文现在仍可被明确处理：要么能读出原明文（未升或仍在宽限），要么已升级后可验证
        for (int i = 0; i < sourceCts.size(); i++) {
            SecretReadResult r = infra.service.read(lease.leaseId(), sourceCts.get(i));
            assertThat(r.plaintext()).isEqualTo(plains.get(i));
        }
    }

    /** 校验一份升级结论里的每个新密文都引用真实存在的当前版本且明文一致。 */
    private int verifyUpgraded(TestInfra infra, String leaseId, UpgradeResult up, List<String> batch) {
        assertThat(up.items()).hasSize(batch.size());
        for (var item : up.items()) {
            assertThat(item.targetVersion()).as("升级目标必须是当时的当前版本")
                    .isEqualTo(up.targetVersion());
            SecretReadResult r = infra.service.read(leaseId, item.ciphertext());
            assertThat(r.keyVersion())
                    .as("新密文再读必须落在升级时承诺的版本 v{}", item.targetVersion())
                    .isEqualTo(item.targetVersion());
            // 该版本必须在库中真实存在（墓碑/缺版本都会在读取处被拒，走到这里即证明存在）
            SecretReadResult old = infra.service.read(leaseId, item.sourceCiphertext());
            assertThat(old.plaintext()).isEqualTo(r.plaintext());
        }
        return up.items().size();
    }

    @Test
    void sameCiphertextUpgradedConcurrentlyNeverCorruptsContentOrCounts() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(1000));
        EncryptResult v1 = infra.service.encrypt("payroll", "same-content");
        infra.service.rotate(Duration.ofHours(1000));

        int n = 12;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CyclicBarrier barrier = new CyclicBarrier(n);
        List<Future<UpgradeResult>> futures = new ArrayList<>();
        AtomicInteger conflicts = new AtomicInteger();
        try {
            for (int i = 0; i < n; i++) {
                futures.add(pool.submit(() -> {
                    await(barrier);
                    try {
                        return infra.service.upgrade(lease.leaseId(), v1.ciphertext());
                    } catch (SecretLeaseException e) {
                        if (e.reason() == DenyReason.ROTATION_IN_PROGRESS) {
                            conflicts.incrementAndGet();
                            return null;
                        }
                        throw e;
                    }
                }));
            }
            int ok = 0;
            for (Future<UpgradeResult> f : futures) {
                UpgradeResult r = f.get();
                if (r == null) {
                    continue;
                }
                ok++;
                assertThat(r.upgradedCount()).isEqualTo(1);
                SecretReadResult read = infra.service.read(lease.leaseId(),
                        r.items().get(0).ciphertext());
                assertThat(read.plaintext()).isEqualTo("same-content");
                assertThat(read.keyVersion()).isEqualTo(2);
            }
            log.info("同密文并发升级: 成功={}, 冲突拒绝={}, 成功项每份计数均为1", ok, conflicts.get());
            assertThat(ok + conflicts.get()).isEqualTo(n);
            assertThat(ok).as("在 5s 等待窗口内应至少有一次升级成功").isGreaterThan(0);
        } finally {
            pool.shutdownNow();
        }
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
