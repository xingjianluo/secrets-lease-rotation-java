package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult;
import com.github.xingjianluo.secretsleaserotationjava.crypto.KeyMaterial;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalKeyManager;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.service.ReadOutcome;
import com.github.xingjianluo.secretsleaserotationjava.service.RotationOutcome;
import com.github.xingjianluo.secretsleaserotationjava.support.MutableTimeSource;
import com.github.xingjianluo.secretsleaserotationjava.support.TestHarness;
import com.github.xingjianluo.secretsleaserotationjava.support.TestLogger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/**
 * 并发轮换冲突与轮换前后密文可解性测试。
 */
class RotationConcurrencyTests {

    /**
     * 在“所有竞争者都读取到同一旧版本、但都尚未 CAS”处设置屏障，
     * 释放后这批 CAS 中恰好一个成功，确定性验证冲突语义。
     */
    static class BarrierKeyManager extends LocalKeyManager {
        private final CyclicBarrier barrier;

        BarrierKeyManager(MutableTimeSource clock, Duration grace, int parties) {
            super(clock, grace);
            this.barrier = new CyclicBarrier(parties);
        }

        @Override
        protected KeyMaterial generateNextKey(int oldVersion) {
            KeyMaterial material = super.generateNextKey(oldVersion);
            awaitQuietly(); // 全部竞争者在此汇合后再一起 CAS
            return material;
        }

        private void awaitQuietly() {
            try {
                barrier.await();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test
    void concurrentRotationsHaveExactlyOneWinner() throws Exception {
        int threads = 16;
        MutableTimeSource clock = MutableTimeSource.startAt(Instant.parse("2026-09-24T00:00:00Z"));
        Duration grace = Duration.ofMinutes(2);
        BarrierKeyManager km = new BarrierKeyManager(clock, grace, threads);
        TestHarness h = TestHarness.withKeyManager(clock, grace, Duration.ofMinutes(5), km);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<RotationOutcome>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(h.service()::rotate));
        }

        int rotated = 0;
        int conflict = 0;
        for (Future<RotationOutcome> f : futures) {
            RotationOutcome outcome = f.get();
            if (outcome instanceof RotationOutcome.Rotated r) {
                rotated++;
                assertEquals(2, r.newVersion());
            } else if (outcome instanceof RotationOutcome.Conflict c) {
                conflict++;
                assertEquals(2, c.currentVersion(), "冲突者观察到的当前版本已是赢家发布的新版本");
            }
        }
        pool.shutdown();

        TestLogger.given("CONCURRENT_ROTATION", threads + " 个线程读取同一版本 v1 后并发 CAS 轮换");
        TestLogger.decided("CONCURRENT_ROTATION",
                "Rotated=" + rotated + "，Conflict=" + conflict + "，最终版本=" + h.service().currentKeyVersion());
        assertEquals(1, rotated, "恰好一个轮换成功");
        assertEquals(threads - 1, conflict, "其余全部以可区分冲突拒绝");
        assertEquals(2, h.service().currentKeyVersion(), "无中间状态：版本只前进一格");

        long conflictAudits = h.auditSink().events().stream()
                .filter(e -> e.result() == AuditResult.DENY_ROTATION_CONFLICT).count();
        assertEquals(threads - 1, conflictAudits, "每个冲突都有审计留痕");
    }

    @Test
    void ciphertextRemainsConsistentAcrossRotation() {
        MutableTimeSource clock = MutableTimeSource.startAt(Instant.parse("2026-09-24T00:00:00Z"));
        TestHarness h = TestHarness.withKeyManager(clock, Duration.ofMinutes(2),
                Duration.ofMinutes(5), new LocalKeyManager(clock, Duration.ofMinutes(2)));
        h.service().registerSubject("alice");
        var lease = h.service().issueLease("alice", "docs", Duration.ofMinutes(10));
        String oldCipher = h.service().seal("stable-secret");

        TestLogger.given("ROTATION_CONSISTENCY",
                "v1 密文=stable-secret", "在宽限期内轮换到 v2", "同一有效租约先后读取旧/新密文");

        ReadOutcome before = h.service().read(lease.token(), "docs", oldCipher);
        assertEquals("stable-secret", ((ReadOutcome.Success) before).plaintext());

        assertTrue(h.service().rotate() instanceof RotationOutcome.Rotated);
        String newCipherAfterV2 = h.service().seal("stable-secret");

        ReadOutcome oldRead = h.service().read(lease.token(), "docs", oldCipher);
        ReadOutcome newRead = h.service().read(lease.token(), "docs", newCipherAfterV2);
        assertEquals("stable-secret", ((ReadOutcome.Success) oldRead).plaintext());
        assertEquals(1, ((ReadOutcome.Success) oldRead).keyVersionUsed());
        assertEquals("stable-secret", ((ReadOutcome.Success) newRead).plaintext());
        assertEquals(2, ((ReadOutcome.Success) newRead).keyVersionUsed());
        TestLogger.decided("ROTATION_CONSISTENCY",
                "宽限期内 v1/v2 密文明文一致，版本号分别标注 1 与 2");

        clock.advance(Duration.ofMinutes(2));
        ReadOutcome expired = h.service().read(lease.token(), "docs", oldCipher);
        assertEquals(Reason.KEY_VERSION_GRACE_EXPIRED, ((ReadOutcome.Denied) expired).reason());
        ReadOutcome fresh = h.service().read(lease.token(), "docs", newCipherAfterV2);
        assertEquals("stable-secret", ((ReadOutcome.Success) fresh).plaintext());
        TestLogger.decided("ROTATION_CONSISTENCY",
                "宽限期结束：v1 拒绝 GRACE_EXPIRED，v2 仍可读（无静默降级）");
    }
}
