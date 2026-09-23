package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.xingjianluo.secretsleaserotationjava.service.LeaseView;
import com.github.xingjianluo.secretsleaserotationjava.service.ReadOutcome;
import com.github.xingjianluo.secretsleaserotationjava.support.TestHarness;
import com.github.xingjianluo.secretsleaserotationjava.support.TestLogger;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/**
 * 不同主体在高并发读取下的隔离性：
 * 每个主体只能用自己作用域的租约解出自己的密文，任何串用都必须表现为 SCOPE_MISMATCH，
 * 成功结果绝不跨主体泄漏。
 */
class ConcurrentReadIsolationTests {

    @Test
    void concurrentReadsNeverCrossSubjects() throws Exception {
        TestHarness h = TestHarness.create(Duration.ofMinutes(2), Duration.ofMinutes(30));
        int subjects = 24;
        int rounds = 20;

        List<LeaseView> leases = new ArrayList<>();
        List<String> ciphers = new ArrayList<>();
        for (int i = 0; i < subjects; i++) {
            String subject = "user-" + i;
            String scope = "scope-" + i;
            String plain = "payload-" + i;
            h.service().registerSubject(subject);
            leases.add(h.service().issueLease(subject, scope, Duration.ofMinutes(30)));
            ciphers.add(h.service().seal(plain));
        }

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch fire = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> leaks = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();

        TestLogger.given("CONCURRENT_READS",
                subjects + " 个主体各有独立作用域租约与密文", "每个主体连续 " + rounds + " 轮："
                        + "一轮读自己的（必须成功且明文匹配），一轮随机读他人密文（必须 SCOPE_MISMATCH）");

        for (int i = 0; i < subjects; i++) {
            final int owner = i;
            futures.add(pool.submit(() -> {
                fire.await();
                for (int round = 0; round < rounds; round++) {
                    // 正确配对：租约 + 同作用域 + 自己的密文
                    ReadOutcome own = h.service().read(
                            leases.get(owner).token(), "scope-" + owner, ciphers.get(owner));
                    if (!(own instanceof ReadOutcome.Success s)
                            || !("payload-" + owner).equals(s.plaintext())) {
                        leaks.add("owner=" + owner + " got " + own);
                    }
                    // 越权配对：用自己的租约读取他人的作用域与密文
                    int other = (owner + 1 + round) % subjects;
                    ReadOutcome cross = h.service().read(
                            leases.get(owner).token(), "scope-" + other, ciphers.get(other));
                    if (!(cross instanceof ReadOutcome.Denied d)
                            || d.reason() != com.github.xingjianluo.secretsleaserotationjava.error.Reason.SCOPE_MISMATCH) {
                        leaks.add("owner=" + owner + " cross read leaked: " + cross);
                    }
                }
                return null;
            }));
        }
        fire.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        TestLogger.decided("CONCURRENT_READS",
                "总读取=" + (subjects * rounds * 2) + "，串用/错放数量=" + leaks.size()
                        + "（0 表示主体间结果完全隔离）");
        assertEquals(List.of(), new ArrayList<>(leaks), () -> "isolation violations: " + leaks);
        // 每条成功读取都有独立审计，主体/作用域标注正确
        long allowedReads = h.auditSink().events().stream()
                .filter(e -> e.action() == com.github.xingjianluo.secretsleaserotationjava.audit.AuditAction.READ
                        && e.result() == com.github.xingjianluo.secretsleaserotationjava.audit.AuditResult.ALLOW)
                .count();
        assertEquals((long) subjects * rounds, allowedReads);
    }
}
