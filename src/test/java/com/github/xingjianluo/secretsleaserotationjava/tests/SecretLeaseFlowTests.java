package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseExpiredException;
import com.github.xingjianluo.secretsleaserotationjava.exception.LeaseRevokedException;
import com.github.xingjianluo.secretsleaserotationjava.exception.ScopeMismatchException;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownSubjectException;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 顺序场景：轮换前后可解性、宽限期边界、租约各类拒绝。
 * 每个用例都打印输入与判定依据，便于人工解释结论。
 */
class SecretLeaseFlowTests {

    private static final Logger log = LoggerFactory.getLogger(SecretLeaseFlowTests.class);

    private SecretLeaseException expectDeny(TestInfra infra, String leaseId, String ct,
                                           DenyReason reason, String desc) {
        log.info("[{}] 输入 leaseId={}, cipherhead={}", desc, leaseId, head(ct));
        try {
            infra.service.read(leaseId, ct);
        } catch (SecretLeaseException e) {
            log.info("[{}] 判定依据={}（期望 {}）msg={}", desc, e.reason(), reason, e.getMessage());
            assertThat(e.reason()).isEqualTo(reason);
            return e;
        }
        throw new AssertionError("[" + desc + "] 期望被拒绝(" + reason + ")但读取成功");
    }

    private static String head(String ct) {
        return ct == null ? "null" : ct.substring(0, Math.min(18, ct.length())) + "...";
    }

    @Test
    void rotateKeepsOldCiphertextDecryptableWithinGraceAndRejectsAfterGrace() {
        TestInfra infra = TestInfra.newInfra();
        String subject = "alice";
        String scope = "payroll";
        Duration grace = Duration.ofHours(24);
        infra.service.registerSubject(subject);
        LeaseIssueResult lease = infra.service.issueLease(subject, scope, Duration.ofHours(100));
        // v1 下加密
        EncryptResult enc = infra.service.encrypt(scope, "salary-4242");
        log.info("用例-轮换宽限: 初始版本=v{}, grace={}", enc.keyVersion(), grace);
        assertThat(infra.service.currentKeyVersion()).isEqualTo(1);

        // 轮换前可读
        SecretReadResult before = infra.service.read(lease.leaseId(), enc.ciphertext());
        assertThat(before.plaintext()).isEqualTo("salary-4242");
        assertThat(before.keyVersion()).isEqualTo(1);
        log.info("轮换前读取成功，明文={}, keyVersion=v{}", before.plaintext(), before.keyVersion());

        // 轮换 v1 -> v2，旧版本进入宽限期
        RotateResult rot = infra.service.rotate(grace);
        log.info("轮换结果: v{} -> v{} at={}", rot.previousVersion(), rot.newVersion(), rot.rotatedAt());
        assertThat(rot.newVersion()).isEqualTo(2);
        assertThat(infra.service.currentKeyVersion()).isEqualTo(2);

        // 新明文用 v2 加密；旧密文仍是 v1
        EncryptResult enc2 = infra.service.encrypt(scope, "salary-5000");
        assertThat(enc2.keyVersion()).isEqualTo(2);

        // 宽限期内：旧 v1 密文仍可解，新 v2 密文也可解
        infra.advance(Duration.ofHours(23));
        assertThat(infra.service.read(lease.leaseId(), enc.ciphertext()).plaintext())
                .as("宽限期内旧版本密文必须仍可解").isEqualTo("salary-4242");
        assertThat(infra.service.read(lease.leaseId(), enc2.ciphertext()).plaintext())
                .isEqualTo("salary-5000");
        log.info("宽限期内(T+23h): v1密文与v2密文均可解");

        // 推进到宽限截止前一刻：仍可解（边界 now == deadline 才算结束）
        infra.advance(Duration.ofMinutes(59)); // T+23h59m
        assertThat(infra.service.read(lease.leaseId(), enc.ciphertext()).plaintext())
                .as("截止前 1 分钟仍在宽限内").isEqualTo("salary-4242");

        // 到达宽限截止时刻 T+24h：旧 v1 密文必须被明确拒绝，而不是静默用 v2 解密
        infra.advance(Duration.ofMinutes(1));
        assertThatThrownBy(() -> infra.service.read(lease.leaseId(), enc.ciphertext()))
                .isInstanceOf(KeyGraceExpiredException.class)
                .satisfies(e -> log.info("宽限截止(T+24h)判定={}, msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
        // 同一份租约下，v2 密文依旧可读——证明不是租约问题，确为旧版本被拒
        assertThat(infra.service.read(lease.leaseId(), enc2.ciphertext()).plaintext())
                .isEqualTo("salary-5000");
        log.info("宽限期后: v1密文明确拒绝(KEY_VERSION_GRACE_EXPIRED)，v2密文正常");
    }

    @Test
    void leaseDenyReasonsAreDistinguishable() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        infra.service.registerSubject("bob");
        EncryptResult enc = infra.service.encrypt("payroll", "top-secret");
        String ct = enc.ciphertext();

        // 1) 不存在的租约
        assertThatThrownBy(() -> infra.service.read("no-such-lease", ct))
                .isInstanceOf(UnknownLeaseException.class)
                .satisfies(e -> log.info("不存在租约判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        LeaseIssueResult aliceLease =
                infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));

        // 2) 作用域不匹配（越权）
        EncryptResult otherScope = infra.service.encrypt("hr-files", "other");
        LeaseIssueResult hrLease = infra.service.issueLease("bob", "hr-files", Duration.ofMinutes(10));
        assertThatThrownBy(() -> {
                    log.info("越权输入: lease.scope=hr-files 去读 cipher.scope=payroll");
                    infra.service.read(hrLease.leaseId(), ct);
                })
                .isInstanceOf(ScopeMismatchException.class)
                .satisfies(e -> log.info("作用域不匹配判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
        // 反向越权同样拒绝
        assertThatThrownBy(() -> infra.service.read(aliceLease.leaseId(), otherScope.ciphertext()))
                .isInstanceOf(ScopeMismatchException.class);

        // 3) 已过期：推进到过期时刻之后（边界 now==expires 即过期）
        infra.advance(Duration.ofMinutes(10));
        assertThatThrownBy(() -> infra.service.read(aliceLease.leaseId(), ct))
                .isInstanceOf(LeaseExpiredException.class)
                .satisfies(e -> log.info("过期判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 4) 已撤销：新发一张并撤销
        LeaseIssueResult lease2 = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));
        infra.service.revoke(lease2.leaseId());
        assertThatThrownBy(() -> infra.service.read(lease2.leaseId(), ct))
                .isInstanceOf(LeaseRevokedException.class)
                .satisfies(e -> log.info("撤销判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));

        // 5) 未登记主体不能签发租约
        assertThatThrownBy(() -> infra.service.issueLease("ghost", "payroll", Duration.ofMinutes(5)))
                .isInstanceOf(UnknownSubjectException.class)
                .satisfies(e -> log.info("未知主体签发判定={} msg={}",
                        ((SecretLeaseException) e).reason(), e.getMessage()));
    }

    @Test
    void unknownKeyVersionAndMalformedCiphertextAreRejected() {
        TestInfra infra = TestInfra.newInfra();
        infra.service.registerSubject("alice");
        LeaseIssueResult lease = infra.service.issueLease("alice", "payroll", Duration.ofMinutes(10));

        // 伪造一个指向不存在版本 v99 的密文
        String fake = "v99:payroll:" + java.util.Base64.getEncoder()
                .encodeToString(new byte[20]);
        SecretLeaseException ex = expectDeny(infra, lease.leaseId(), fake,
                DenyReason.UNKNOWN_KEY_VERSION, "未知版本密文");
        assertThat(ex).isNotNull();

        expectDeny(infra, lease.leaseId(), "garbage",
                DenyReason.UNKNOWN_KEY_VERSION, "格式损坏密文");
    }
}
