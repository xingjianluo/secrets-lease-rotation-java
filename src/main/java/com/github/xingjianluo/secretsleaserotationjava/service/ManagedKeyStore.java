package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionNotPurgeableException;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyVersionPurgedException;
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

    /** 升级/清理等待版本变更锁的最长时间；拿不到说明有持续的版本变更，按冲突拒绝并可重试。 */
    private static final long MUTATION_LOCK_WAIT_MILLIS = 5_000L;

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

    /**
     * 清理一个退役版本：仅当它不是当前版本、不是已清理墓碑、且宽限期已结束
     * （now &gt;= graceDeadline，边界时刻即允许清理，与读取侧的左闭右开一致）时允许移出。
     * 与轮换、升级、其它清理互斥（同一把版本变更锁）；清理用墓碑替换版本，
     * 仍可被明确识别为“已移除”，而不是伪装成“从未存在”。
     */
    public PurgeOutcome purge(int version, Runnable preCommitAudit) {
        try {
            if (!rotationLock.tryLock(MUTATION_LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS)) {
                throw new RotationConflictException("已有密钥版本变更正在进行，本次清理被拒绝");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("清理等待被中断");
        }
        try {
            Snapshot before = snapshot.get();
            Instant now = Instant.now(clock);
            KeyVersion kv = before.versions().get(version);
            if (kv == null) {
                throw new UnknownKeyVersionException("密钥版本不存在，无法清理: v" + version);
            }
            if (kv.isPurged()) {
                throw new KeyVersionPurgedException(
                        "密钥版本 v" + version + " 已被清理（清理于 " + kv.purgedAt() + "）");
            }
            if (kv.isCurrent()) {
                throw new KeyVersionNotPurgeableException(
                        "当前密钥版本 v" + version + " 不允许清理");
            }
            if (kv.graceDeadline() == null || now.isBefore(kv.graceDeadline())) {
                throw new KeyVersionNotPurgeableException("退役密钥版本 v" + version
                        + " 宽限期尚未结束(deadline=" + kv.graceDeadline() + "，now=" + now
                        + ")，拒绝清理");
            }
            KeyVersion tombstone = kv.purgedCopy(now);
            Map<Integer, KeyVersion> next = new java.util.HashMap<>(before.versions());
            next.put(version, tombstone);
            // 先审计：审计落不下来则直接中止，快照保持原样（fail-closed）
            preCommitAudit.run();
            // 唯一状态发布点：整体快照原子切换，读侧不可能看到“清了一半”
            snapshot.set(new Snapshot(Map.copyOf(next), before.currentVersion()));
            return new PurgeOutcome(version, now, kv.graceDeadline());
        } finally {
            rotationLock.unlock();
        }
    }

    /**
     * 在版本变更锁内原子地执行一次“读当前版本 → 产出”的动作（升级专用）。
     * 动作执行期间不会穿插轮换或清理，因此产出的新密文引用的必然是当时真实存在的
     * 当前版本，升级的外部结论要么完整成功要么整批拒绝。
     */
    public <T> T withMutationLock(java.util.function.Supplier<T> action) {
        boolean acquired;
        try {
            acquired = rotationLock.tryLock(MUTATION_LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("升级等待被中断");
        }
        if (!acquired) {
            throw new RotationConflictException("密钥版本正在变更（轮换/清理），本次升级被拒绝，请重试");
        }
        try {
            return action.get();
        } finally {
            rotationLock.unlock();
        }
    }

    /** 清理输出。 */
    public record PurgeOutcome(int version, Instant purgedAt, Instant graceDeadline) {
    }

    /** 轮换输出。 */
    public record RotationOutcome(int previousVersion, int newVersion, Instant rotatedAt) {
    }
}
