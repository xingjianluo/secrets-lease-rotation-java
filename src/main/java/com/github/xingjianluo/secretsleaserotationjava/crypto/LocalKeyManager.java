package com.github.xingjianluo.secretsleaserotationjava.crypto;

import com.github.xingjianluo.secretsleaserotationjava.clock.TimeSource;
import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 本地密钥材料管理器（模拟受管密钥服务/KMS）。
 *
 * <p>版本策略：初始版本为 1；每次轮换生成全新 AES-256 密钥并把版本号 +1。
 * 旧版本被取代的时刻（retiredAt）是宽限期计时的唯一起点：
 * now &gt;= retiredAt + gracePeriod 时，该版本密文被明确拒绝（KEY_VERSION_GRACE_EXPIRED），
 * 绝不静默使用其它版本降级解密。</p>
 *
 * <p>并发策略：全部可变状态收敛为一个不可变 {@link KeyState}，轮换通过 CAS 原子发布。
 * 对同一当前版本竞争的一批并发请求中恰好一个 CAS 成功；其余请求看到状态已变即冲突返回，
 * 其已生成的密钥材料直接丢弃，不发布任何中间状态。</p>
 */
public class LocalKeyManager {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final TimeSource clock;
    private final Duration gracePeriod;
    private final SecureRandom random = new SecureRandom();
    private final AtomicReference<KeyState> state;

    /** 不可变密钥状态：当前版本 + 全部历史版本材料 + 旧版本退役时刻。 */
    private record KeyState(int currentVersion,
                           Map<Integer, KeyMaterial> keysByVersion,
                           Map<Integer, Instant> retiredAtByVersion) {
    }

    public LocalKeyManager(TimeSource clock, Duration gracePeriod) {
        this.clock = clock;
        this.gracePeriod = gracePeriod;
        Map<Integer, KeyMaterial> initial = new HashMap<>();
        initial.put(1, new KeyMaterial(1, generateKey(), clock.now()));
        this.state = new AtomicReference<>(new KeyState(1, Map.of(1, initial.get(1)), Map.of()));
    }

    /** 当前（最新）密钥版本号。 */
    public int currentVersion() {
        return state.get().currentVersion();
    }

    /** 使用当前版本密钥加密，返回携带版本号的受管密文。 */
    public ManagedCiphertext seal(String plaintext) {
        KeyState snapshot = state.get();
        int version = snapshot.currentVersion();
        SecretKey key = snapshot.keysByVersion().get(version).key();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return new ManagedCiphertext(version, iv, ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    /**
     * 尝试轮换：基于读取到的当前状态构造下一状态并 CAS 原子发布。
     *
     * @return 成功时为新版本号；并发竞争失败（状态已被他人推进）时返回 0 或负数形式的冲突标记——
     *     实际通过 {@link #tryRotate()} 返回 {@link RotationResult} 携带冲突后的真实当前版本，
     *     本方法保留为布尔便捷接口。
     */
    public boolean rotate() {
        return tryRotate().rotated();
    }

    /**
     * 轮换并返回详细结果：
     * 成功携带新版本号；冲突时携带 CAS 失败后重新观察到的当前版本（即赢家发布的版本），
     * 且本线程生成的密钥材料直接丢弃，不发布任何中间状态。
     */
    public RotationResult tryRotate() {
        KeyState snapshot = state.get();
        int oldVersion = snapshot.currentVersion();
        // 先离线生成新材料；此时对外状态完全不变。
        KeyMaterial next = generateNextKey(oldVersion);

        Map<Integer, KeyMaterial> newKeys = new HashMap<>(snapshot.keysByVersion());
        newKeys.put(next.version(), next);
        Map<Integer, Instant> newRetired = new HashMap<>(snapshot.retiredAtByVersion());
        newRetired.put(oldVersion, next.createdAt());
        KeyState updated = new KeyState(next.version(), Map.copyOf(newKeys), Map.copyOf(newRetired));

        // 只有从同一旧状态出发的 CAS 能成功；冲突者重新读取赢家发布后的版本。
        if (state.compareAndSet(snapshot, updated)) {
            return new RotationResult(true, next.version());
        }
        return new RotationResult(false, state.get().currentVersion());
    }

    /** 轮换尝试结果：rotated=false 时 version 为冲突后观察到的当前版本。 */
    public record RotationResult(boolean rotated, int version) {
    }

    /**
     * 按版本与宽限期策略解密：
     * <ol>
     *   <li>版本从未存在：KEY_VERSION_UNKNOWN；</li>
     *   <li>当前版本：直接解密；</li>
     *   <li>旧版本：now &lt; retiredAt + grace 才允许，否则 KEY_VERSION_GRACE_EXPIRED；</li>
     *   <li>认证失败/数据损坏：BAD_CIPHERTEXT。</li>
     * </ol>
     */
    public String openDuringGrace(ManagedCiphertext ciphertext) {
        KeyState snapshot = state.get();
        int version = ciphertext.keyVersion();
        KeyMaterial material = snapshot.keysByVersion().get(version);
        if (material == null) {
            throw new ServiceException(Reason.KEY_VERSION_UNKNOWN,
                    "key version " + version + " is unknown to this manager");
        }
        Instant now = clock.now();
        if (version != snapshot.currentVersion()) {
            Instant retiredAt = snapshot.retiredAtByVersion().get(version);
            Instant graceEnd = retiredAt.plus(gracePeriod);
            if (!now.isBefore(graceEnd)) {
                throw new ServiceException(Reason.KEY_VERSION_GRACE_EXPIRED,
                        "key version " + version + " retired at " + retiredAt
                                + " is outside grace period ending at " + graceEnd + " (now=" + now + ")");
            }
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, material.key(),
                    new GCMParameterSpec(TAG_BITS, ciphertext.iv()));
            byte[] plaintext = cipher.doFinal(ciphertext.bytes());
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new ServiceException(Reason.BAD_CIPHERTEXT,
                    "ciphertext failed authentication for key version " + version, e);
        }
    }

    /**
     * 生成下一版本密钥材料。protected 以便测试在“已读取旧版本、尚未 CAS”窗口插入同步点，
     * 确定性地构造并发轮换批次。
     */
    protected KeyMaterial generateNextKey(int oldVersion) {
        return new KeyMaterial(oldVersion + 1, generateKey(), clock.now());
    }

    private static SecretKey generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to generate AES key", e);
        }
    }
}
