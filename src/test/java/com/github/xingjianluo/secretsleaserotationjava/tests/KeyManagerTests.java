package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.xingjianluo.secretsleaserotationjava.crypto.CiphertextCodec;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalKeyManager;
import com.github.xingjianluo.secretsleaserotationjava.crypto.ManagedCiphertext;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import com.github.xingjianluo.secretsleaserotationjava.support.MutableTimeSource;
import com.github.xingjianluo.secretsleaserotationjava.support.TestLogger;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * 密钥版本引入/轮换与宽限期边界测试。
 */
class KeyManagerTests {

    private static final Instant T0 = Instant.parse("2026-09-24T00:00:00Z");
    private static final Duration GRACE = Duration.ofMinutes(2);

    @Test
    void oldVersionDecryptsWithinGraceAndIsRejectedAfter() {
        MutableTimeSource clock = MutableTimeSource.startAt(T0);
        LocalKeyManager km = new LocalKeyManager(clock, GRACE);

        // 轮换前用 v1 加密
        ManagedCiphertext old = km.seal("secret-before-rotation");
        assertEquals(1, old.keyVersion());

        TestLogger.given("GRACE_BOUNDARY",
                "密文由 v1 在 T0 加密", "T0 时刻轮换到 v2", "宽限期=2m");
        TestLogger.decided("GRACE_BOUNDARY", "轮换成功，v1 进入宽限期");

        boolean rotated = km.rotate();
        org.junit.jupiter.api.Assertions.assertTrue(rotated);
        assertEquals(2, km.currentVersion());

        // 新明文用 v2
        ManagedCiphertext fresh = km.seal("secret-after-rotation");
        assertEquals(2, fresh.keyVersion());

        // 宽限边界前一刻（1m59.999999999s）：旧版本必须仍可解
        clock.advance(Duration.ofMinutes(2).minusNanos(1));
        assertEquals("secret-before-rotation", km.openDuringGrace(old));
        assertEquals("secret-after-rotation", km.openDuringGrace(fresh));
        TestLogger.decided("GRACE_BOUNDARY", "now < retiredAt+2m：v1 密文仍可解，v2 正常");

        // 到达边界（精确等于 retiredAt + grace）：必须明确拒绝，不静默降级
        clock.advance(Duration.ofNanos(1));
        ServiceException ex = assertThrows(ServiceException.class, () -> km.openDuringGrace(old));
        assertEquals(Reason.KEY_VERSION_GRACE_EXPIRED, ex.reason());
        TestLogger.decided("GRACE_BOUNDARY",
                "now == retiredAt+2m：v1 被明确拒绝 KEY_VERSION_GRACE_EXPIRED（不降级到 v2）");

        // 当前版本不受影响
        assertEquals("secret-after-rotation", km.openDuringGrace(fresh));
    }

    @Test
    void unknownVersionAndTamperedCiphertextAreRejected() {
        MutableTimeSource clock = MutableTimeSource.startAt(T0);
        LocalKeyManager km = new LocalKeyManager(clock, GRACE);
        TestLogger.given("UNKNOWN_VERSION", "密文标注版本 99（系统从未存在）");
        ServiceException unknown = assertThrows(ServiceException.class,
                () -> km.openDuringGrace(new ManagedCiphertext(99, new byte[12], new byte[16])));
        assertEquals(Reason.KEY_VERSION_UNKNOWN, unknown.reason());
        TestLogger.decided("UNKNOWN_VERSION", "拒绝原因=" + unknown.reason());

        ManagedCiphertext valid = km.seal("x");
        byte[] tampered = valid.bytes().clone();
        tampered[0] ^= 0x01;
        TestLogger.given("BAD_CIPHERTEXT", "密文认证标签对应数据被翻转 1 字节");
        ServiceException bad = assertThrows(ServiceException.class,
                () -> km.openDuringGrace(new ManagedCiphertext(valid.keyVersion(), valid.iv(), tampered)));
        assertEquals(Reason.BAD_CIPHERTEXT, bad.reason());
        TestLogger.decided("BAD_CIPHERTEXT", "拒绝原因=" + bad.reason());

        ServiceException parse = assertThrows(ServiceException.class,
                () -> CiphertextCodec.decode("not-a-managed-ciphertext"));
        assertEquals(Reason.BAD_CIPHERTEXT, parse.reason());
    }
}
