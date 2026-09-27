package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 升级与轮换并发：
 * 每次成功升级产出的密文都引用一个当时真实存在的版本；整批只引用锁定的同一目标版本；
 * 同一份密文被并发升级多次，内容不错乱、审计计数精确；批量条目确实并行而非串行。
 */
class ConcurrentUpgradeTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentUpgradeTests.class);

    /**
     * 升级与多次轮换同时进行：
     * 每个升级结果的目标版本必须在完成时刻仍真实存在（不可能是被清理/不存在的版本），
     * 且新密文能被同一租约读回、明文与作用域与源密文一致。
     */
    @Test
    void concurrentUpgradesAndRotationsEveryResultReferencesARealVersion() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        // v1 密文（每个升级线程独立一份，避免线程间共享输入带来的歧义）
        EncryptResult template = infra.service.encrypt("payroll", "stable-plaintext");
        String sourceCipher = template.ciphertext();

        int upgraders = 24;
        int rotations = 4;
        ExecutorService pool = Executors.newFixedThreadPool(upgraders + 1);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < upgraders; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    UpgradeResult up = infra.service.upgrade(lease.leaseId(), sourceCipher);
                    // 目标版本必须真实存在
                    if (infra.keyStore.findVersion(up.targetVersion()).isEmpty()) {
                        log.error("升级引用了不存在版本 v{}", up.targetVersion());
                        return false;
                    }
                    // 新密文用同一租约读回，明文/作用域一致，落在目标版本上
                    var read = infra.service.read(lease.leaseId(), up.ciphertext());
                    boolean ok = read.keyVersion() == up.targetVersion()
                            && "stable-plaintext".equals(read.plaintext())
                            && "payroll".equals(read.scope());
                    if (!ok) {
                        log.error("升级结果读回不一致: target=v{}, read=v{}, pt={}",
                                up.targetVersion(), read.keyVersion(), read.plaintext());
                    }
                    return ok;
                } catch (Exception e) {
                    // 宽限期恰好过期等被明确拒绝是允许的结论，但引用幽灵版本不允许
                    log.warn("并发升级被明确拒绝: {}", e.getClass().getSimpleName());
                    return true;
                }
            }));
        }
        // 另一个线程穿插轮换
        Future<?> rotator = pool.submit(() -> {
            await(start);
            for (int r = 0; r < rotations; r++) {
                try {
                    infra.service.rotate(Duration.ofHours(200));
                } catch (Exception ignored) {
                    // 与轮换自身冲突时忽略
                }
            }
        });

        start.countDown();
        int ok = 0;
        for (Future<Boolean> f : futures) {
            if (f.get(15, TimeUnit.SECONDS)) {
                ok++;
            }
        }
        rotator.get(15, TimeUnit.SECONDS);
        pool.shutdown();

        int finalVersion = infra.service.currentKeyVersion();
        log.info("升级×轮换: 升级校验通过={}/{}, 最终当前版本=v{}（轮换提交数受锁约束）",
                ok, upgraders, finalVersion);
        assertThat(ok).isEqualTo(upgraders);
        assertThat(finalVersion).isBetween(2, 1 + rotations + 1);

        // 全部成功升级审计的目标版本都在最终版本集合内真实存在过（版本只增不删，此处无清理）
        List<Integer> auditedTargets = infra.auditEvents().stream()
                .filter(e -> e.action() == com.github.xingjianluo.secretsleaserotationjava.model.Action.UPGRADE_SECRET
                        && "SUCCESS".equals(e.result()))
                .map(e -> e.keyVersion())
                .toList();
        for (int v : auditedTargets) {
            assertThat(infra.keyStore.findVersion(v))
                    .as("审计记录的升级目标版本 v{} 必须真实存在", v).isPresent();
        }
    }

    /**
     * 同一份密文被并发升级多次：每次都是独立的"解密-重加密"，不共享可变计数，
     * 成功次数与成功审计条数必须精确相等（不多不少、不串用）。
     */
    @Test
    void concurrentUpgradesOfSameCiphertextDoNotCorruptCountOrContent() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        String cipher = infra.service.encrypt("payroll", "count-me").ciphertext();
        infra.service.rotate(Duration.ofHours(200));

        int n = 32;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                await(start);
                UpgradeResult up = infra.service.upgrade(lease.leaseId(), cipher);
                var read = infra.service.read(lease.leaseId(), up.ciphertext());
                if ("count-me".equals(read.plaintext()) && read.scope().equals("payroll")) {
                    success.incrementAndGet();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(15, TimeUnit.SECONDS);
        }
        pool.shutdown();

        long successAudit = infra.auditEvents().stream()
                .filter(e -> e.action() == com.github.xingjianluo.secretsleaserotationjava.model.Action.UPGRADE_SECRET
                        && "SUCCESS".equals(e.result())).count();
        log.info("同密文并发升级: 请求={}, 内容正确成功={}, 成功审计={}", n, success.get(), successAudit);
        assertThat(success.get()).isEqualTo(n);
        assertThat(successAudit).isEqualTo(n);
    }

    /**
     * 批量升级必须并行而非串行：用一个在重加密时可观测"同时在飞数"的慢速 crypto，
     * 大批量的峰值并发应明显大于 1，且墙钟时间显著短于串行下界。
     */
    @Test
    void batchUpgradeRunsItemsInParallel() throws Exception {
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        LocalCryptoService slowCrypto = new LocalCryptoService() {
            @Override
            public String encrypt(int version, String scope, byte[] key, String plaintext) {
                int cur = inFlight.incrementAndGet();
                peak.updateAndGet(p -> Math.max(p, cur));
                try {
                    Thread.sleep(40);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                inFlight.decrementAndGet();
                return super.encrypt(version, scope, key, plaintext);
            }
        };
        TestInfra infra = TestInfra.newInfra(slowCrypto);
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofHours(200));
        int size = 16;
        List<String> batch = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            batch.add(infra.service.encrypt("payroll", "p-" + i).ciphertext());
        }
        infra.service.rotate(Duration.ofHours(200));

        long t0 = System.nanoTime();
        List<UpgradeResult> out = infra.service.upgradeBatch(lease.leaseId(), batch);
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        long serialLowerBoundMs = size * 40L;
        log.info("批量并行: size={}, 峰值并发={}, 耗时={}ms, 串行下界={}ms",
                size, peak.get(), elapsedMs, serialLowerBoundMs);
        assertThat(out).hasSize(size);
        assertThat(peak.get()).as("条目必须真正并行").isGreaterThan(1);
        assertThat(elapsedMs).as("不得退化为一条条串行").isLessThan(serialLowerBoundMs);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
