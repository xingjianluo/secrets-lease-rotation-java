package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.RotationConflictException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 并发轮换：同一时刻只允许一个轮换成功，其余必须以 ROTATION_IN_PROGRESS 拒绝，
 * 且版本号连续、读侧永远观察不到中间状态。
 */
class ConcurrentRotationTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRotationTests.class);

    /**
     * 确定性冲突：让"新密钥材料生成"在关键区内短暂等待，
     * 保证第二个轮换在第一个尚未发布时进入，从而必然竞争同一把锁。
     */
    @Test
    void concurrentRotateOnlyOneSucceedsOthersConflict() throws Exception {
        ReentrantLock gate = new ReentrantLock();
        gate.lock(); // 关键区内的密钥生成会阻塞在此，直到测试放行
        AtomicInteger rotationKeyCalls = new AtomicInteger();
        LocalCryptoService slowCrypto = new LocalCryptoService() {
            @Override
            public byte[] generateKey() {
                if (rotationKeyCalls.incrementAndGet() > 1) {
                    // 仅"轮换产生的"新密钥在此排队；初始 v1 密钥不受影响
                    gate.lock();
                    gate.unlock();
                }
                return super.generateKey();
            }
        };
        TestInfra infra = TestInfra.newInfra(slowCrypto);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);

        CallOutcome a = new CallOutcome();
        CallOutcome b = new CallOutcome();
        Runnable first = () -> {
            ready.countDown();
            await(start);
            try {
                RotateResult r = infra.service.rotate(Duration.ofHours(1));
                a.success = r.newVersion();
            } catch (RotationConflictException e) {
                a.conflict = true;
            }
        };
        Runnable second = () -> {
            ready.countDown();
            await(start);
            // 略微等待，确保第一个已进入关键区并卡在密钥生成上
            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            try {
                RotateResult r = infra.service.rotate(Duration.ofHours(1));
                b.success = r.newVersion();
            } catch (RotationConflictException e) {
                b.conflict = true;
            }
        };

        pool.submit(first);
        pool.submit(second);
        assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
        start.countDown();

        // 给两个线程时间：第一个进入关键区，第二个撞上锁
        Thread.sleep(200);
        // 冲突应已发生且此时第一个尚未提交（current 仍为 v1，无中间状态）
        int versionWhileInFlight = infra.service.currentKeyVersion();
        log.info("轮换关键区进行中观察到的当前版本=v{}（期望保持 v1）", versionWhileInFlight);
        assertThat(versionWhileInFlight)
                .as("关键区未提交前不得观察到中间状态")
                .isEqualTo(1);

        gate.unlock(); // 放行第一个完成
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        boolean exactlyOneSuccess = (a.success > 0) ^ (b.success > 0);
        boolean exactlyOneConflict = a.conflict ^ b.conflict;
        log.info("结果: A(success={}, conflict={}) B(success={}, conflict={})",
                a.success, a.conflict, b.success, b.conflict);
        assertThat(exactlyOneSuccess).as("恰好一个轮换成功").isTrue();
        assertThat(exactlyOneConflict).as("另一个必须为冲突拒绝").isTrue();
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);
        log.info("最终当前版本=v2，无中间状态遗留");
    }

    /**
     * 高并发压力：大量轮换中每个版本恰好被一个线程推进，版本连续，
     * 成功者数 + 冲突者数 == 总请求数。
     */
    @Test
    void stressManyConcurrentRotationsAreSerialized() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Integer> successVersions = new ConcurrentLinkedQueue<>();
        AtomicInteger conflicts = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                await(start);
                try {
                    RotateResult r = infra.service.rotate(Duration.ofMinutes(30));
                    successVersions.add(r.newVersion());
                } catch (RotationConflictException e) {
                    conflicts.incrementAndGet();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        List<Integer> sorted = successVersions.stream().sorted().toList();
        log.info("压力轮换: 请求={}, 成功={}, 冲突={}, 成功版本={}",
                threads, sorted.size(), conflicts.get(), sorted);

        assertThat(sorted.size() + conflicts.get()).isEqualTo(threads);
        // 成功版本必须恰好是 2..N，每个一次：无丢失、无重复、无跳号中间态
        for (int v = 2; v <= sorted.size() + 1; v++) {
            final int expected = v;
            assertThat(sorted).contains(expected);
        }
        assertThat(sorted).doesNotHaveDuplicates().hasSize((int) sorted.stream().count());
        assertThat(infra.service.currentKeyVersion()).isEqualTo(sorted.size() + 1);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    static final class CallOutcome {
        volatile int success;
        volatile boolean conflict;
    }
}
