package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.RotationConflictException;
import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException;
import com.github.xingjianluo.secretsleaserotationjava.model.KeyVersion;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 受管密钥版本库：保存 current 版本与若干 retired 版本。
 *
 * <p>并发安全由两点保证：
 * <ul>
 *   <li>整个版本集合是不可变快照，经 {@link AtomicReference} 原子发布——
 *       任何并发读取看到的要么是轮换前、要么是轮换后的完整状态，不存在中间状态。</li>
 *   <li>轮换使用 {@link ReentrantLock#tryLock()}：同时只有一个轮换能拿到锁，
 *       其余立即以 {@link RotationConflictException} 拒绝，且不会改动任何状态。</li>
 * </ul>
 */
@Component
public class ManagedKeyStore {

    /** 轮换关键区持有的最长时间；超时未拿到锁也按冲突处理，而不是无限等待。 */
    private static final long LOCK_WAIT_MILLIS = 0L;

    private record Snapshot(Map<Integer, KeyVersion> versions, int currentVersion) {
    }

    private final AtomicReference<Snapshot> snapshot;
    private final ReentrantLock rotationLock = new ReentrantLock();
    private final Clock clock;

    public ManagedKeyStore(Clock clock, LocalCryptoService crypto) {
        this.clock = clock;
        Instant now = Instant.now(clock);
        KeyVersion v1 = new KeyVersion(1, crypto.generateKey(), now, true);
        this.snapshot = new AtomicReference<>(
                new Snapshot(Map.of(1, v1), 1));
    }

    /**
     * 轮换：旧 current 退役（给宽限期），生成新 current。
     * 并发轮换只有一个成功，其余抛 {@link RotationConflictException} 且不留中间状态。
     *
     * @param gracePeriod  旧版本宽限期
     * @param keyGenerator 新版本密钥材料生成器（参数为新版本号）
     */
    public RotationOutcome rotate(Duration gracePeriod, Function<Integer, byte[]> keyGenerator) {
        boolean acquired;
        try {
            acquired = rotationLock.tryLock(LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("轮换等待被中断");
        }
        if (!acquired) {
            throw new RotationConflictException("已有轮换正在进行，本次并发轮换被拒绝");
        }
        try {
            Snapshot before = snapshot.get();
            Instant now = Instant.now(clock);
            int newVersionNumber = before.currentVersion() + 1;

            KeyVersion oldCurrent = before.versions().get(before.currentVersion());
            KeyVersion retired = oldCurrent.retiredCopy(now, now.plus(gracePeriod));
            KeyVersion fresh = new KeyVersion(newVersionNumber,
                    keyGenerator.apply(newVersionNumber), now, true);

            Map<Integer, KeyVersion> next = new java.util.HashMap<>(before.versions());
            next.put(retired.version(), retired);
            next.put(fresh.version(), fresh);

            // 唯一的状态发布点：一次性整体切换，读侧不可能观察到半成品
            snapshot.set(new Snapshot(Map.copyOf(next), newVersionNumber));
            return new RotationOutcome(oldCurrent.version(), fresh.version(), now);
        } finally {
            rotationLock.unlock();
        }
    }

    public KeyVersion current() {
        Snapshot s = snapshot.get();
        return s.versions().get(s.currentVersion());
    }

    /** 取指定版本；不存在则明确拒绝（不回退到 current，不静默降级）。 */
    public KeyVersion requireVersion(int version) {
        KeyVersion kv = snapshot.get().versions().get(version);
        if (kv == null) {
            throw new UnknownKeyVersionException("密钥版本不存在: v" + version);
        }
        return kv;
    }

    public Optional<KeyVersion> findVersion(int version) {
        return Optional.ofNullable(snapshot.get().versions().get(version));
    }

    public List<KeyVersion> allVersions() {
        Snapshot s = snapshot.get();
        return s.versions().values().stream()
                .sorted(java.util.Comparator.comparingInt(KeyVersion::version))
                .collect(Collectors.toList());
    }

    /** 轮换输出。 */
    public record RotationOutcome(int previousVersion, int newVersion, Instant rotatedAt) {
    }
}
