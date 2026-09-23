package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 并发读取隔离：多个主体/作用域并发读取时，每次都只能读到与自己租约作用域一致的明文，
 * 不允许出现跨主体/跨作用域的结果串用。读取路径不做共享结果缓存，每次独立按租约判定。
 */
class ConcurrentReadIsolationTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentReadIsolationTests.class);

    @Test
    void concurrentReadsNeverCrossSubjectResults() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        int subjects = 8;
        int rounds = 50;

        List<String> scopes = new ArrayList<>();
        List<String> secrets = new ArrayList<>();
        List<String> leaseIds = new ArrayList<>();
        List<String> ciphertexts = new ArrayList<>();

        for (int i = 0; i < subjects; i++) {
            String subject = "user-" + i;
            String scope = "scope-" + i;
            String secret = "secret-only-for-" + i;
            infra.service.registerSubject(subject);
            LeaseIssueResult lease =
                    infra.service.issueLease(subject, scope, Duration.ofHours(1));
            EncryptResult enc = infra.service.encrypt(scope, secret);
            scopes.add(scope);
            secrets.add(secret);
            leaseIds.add(lease.leaseId());
            ciphertexts.add(enc.ciphertext());
        }

        int total = subjects * rounds;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int r = 0; r < rounds; r++) {
            for (int i = 0; i < subjects; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    start.await();
                    SecretReadResult res = infra.service.read(leaseIds.get(idx), ciphertexts.get(idx));
                    boolean ok = res.subject().equals("user-" + idx)
                            && res.scope().equals(scopes.get(idx))
                            && res.plaintext().equals(secrets.get(idx));
                    if (!ok) {
                        log.error("串用结果! idx={} 读到 subject={}, scope={}, plaintext={}",
                                idx, res.subject(), res.scope(), res.plaintext());
                    }
                    return ok;
                }));
            }
        }
        start.countDown();

        int matched = 0;
        for (Future<Boolean> f : futures) {
            if (f.get(10, TimeUnit.SECONDS)) {
                matched++;
            }
        }
        pool.shutdown();
        log.info("并发读取隔离: 总读取={}, 主体/作用域/明文全部一致={}", total, matched);
        assertThat(matched).as("任何一次读取都不得串用其它主体的结果").isEqualTo(total);
    }

    @Test
    void concurrentCrossScopeAccessAlwaysDenied() throws Exception {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.registerSubject("bob");
        var aliceLease = infra.service.issueLease("alice", "a", Duration.ofHours(1));
        var bobLease = infra.service.issueLease("bob", "b", Duration.ofHours(1));
        var ctA = infra.service.encrypt("a", "AAA").ciphertext();
        var ctB = infra.service.encrypt("b", "BBB").ciphertext();

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        // 双方反复"拿着自己的租约去读对方作用域的密文"，必须全部越权拒绝
        for (int i = 0; i < 100; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return crossDenied(infra, aliceLease.leaseId(), ctB)
                        & crossDenied(infra, bobLease.leaseId(), ctA);
            }));
        }
        start.countDown();
        int denied = 0;
        for (Future<Boolean> f : futures) {
            if (f.get(10, TimeUnit.SECONDS)) {
                denied++;
            }
        }
        pool.shutdown();
        log.info("并发越权: 越权尝试批次={}, 全部 SCOPE_MISMATCH 拒绝={}", 100, denied == 100);
        assertThat(denied).isEqualTo(100);
    }

    private static boolean crossDenied(TestInfra infra, String leaseId, String ct) {
        try {
            infra.service.read(leaseId, ct);
            return false;
        } catch (com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
