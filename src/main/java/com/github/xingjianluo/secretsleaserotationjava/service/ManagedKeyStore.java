package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalCryptoService;
import com.github.xingjianluo.secretsleaserotationjava.exception.KeyGraceExpiredException;
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
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 受管密钥版本库：保存 current 版本与若干 retired 版本，以及已被清理版本的墓碑。
 *
 * <p>并发安全由两点保证：
 * <ul>
 *   <li>整个版本集合是不可变快照，经 {@link AtomicReference} 原子发布——
 *       任何并发读取看到的要么是轮换/清理前、要么是轮换/清理后的完整状态，不存在中间状态。</li>
 *   <li>轮换与清理共用同一把 {@link ReentrantReadWriteLock} 的写锁（{@code tryLock}，不等待）：
 *       同时只有一个变更能进入关键区，其余立即以 {@link RotationConflictException} 拒绝，
 *       且不会改动任何状态。</li>
 * </ul>
 *
 * <p>升级的"提交"（重加密完成后、把新密文交给调用方之前）通过
 * {@link #commitUpgrade} 在读锁关键区内完成：读锁与轮换/清理的写锁<b>互斥</b>，
 * 因此升级提交与清理之间存在确定的先后顺序（线性化点）——
 * 清理先于提交则提交时必能看到墓碑并拒绝升级；提交先于清理则升级成功、
 * 返回的密文引用的版本在返回那一刻仍然真实存在且可读。升级之间共享读锁，互不阻塞，
 * 批量升级的并行度不被串行化（耗时的解密/重加密全部发生在读锁之外）。
 *
 * <p>清理（{@link #purge}）只移除密钥材料，仍保留版本号的"墓碑"（{@link PurgedVersion}），
 * 因此读侧可以明确区分"版本曾经存在但已被清理"（{@code KEY_VERSION_PURGED}）与
 * "版本从未存在"（{@code UNKNOWN_KEY_VERSION}），绝不用当前版本顶替。
 */
@Component
public class ManagedKeyStore {

    /** 变更关键区持有的最长时间；超时未拿到锁也按冲突处理，而不是无限等待。 */
    private static final long LOCK_WAIT_MILLIS = 0L;

    /**
     * 升级提交等待写锁退场的最长时间。写锁关键区只做内存快照替换，正常情况下极短；
     * 超时按冲突明确拒绝（fail-closed），不产出新密文。
     */
    private static final long COMMIT_LOCK_WAIT_MILLIS = 5_000L;

    private record Snapshot(Map<Integer, KeyVersion> versions,
                            Map<Integer, PurgedVersion> purged, int currentVersion) {
    }

    /** 已清理版本的墓碑：密钥材料已删除，仅保留可解释/可审计的元数据。 */
    public record PurgedVersion(int version, Instant retiredAt,
                                Instant graceDeadline, Instant purgedAt) {
    }

    /** 清理输出。 */
    public record PurgeOutcome(int version, Instant purgedAt, Instant graceDeadline) {
    }

    private final AtomicReference<Snapshot> snapshot;
    // 公平锁：轮换/清理一旦排队等待写锁，后到的升级提交（读锁）不再插队，
    // 避免"升级提交源源不断 → 轮换永远拿不到锁"的写者饥饿；读锁之间仍共享，批量并行不受影响。
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true);
    private final Clock clock;

    public ManagedKeyStore(Clock clock, LocalCryptoService crypto) {
        this.clock = clock;
        Instant now = Instant.now(clock);
        KeyVersion v1 = new KeyVersion(1, crypto.generateKey(), now, true);
        this.snapshot = new AtomicReference<>(
                new Snapshot(Map.of(1, v1), Map.of(), 1));
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
            acquired = rwLock.writeLock().tryLock(LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("轮换等待被中断");
        }
        if (!acquired) {
            throw new RotationConflictException("已有密钥变更（轮换/清理）正在进行，本次并发轮换被拒绝");
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
            snapshot.set(new Snapshot(Map.copyOf(next), before.purged(), newVersionNumber));
            return new RotationOutcome(oldCurrent.version(), fresh.version(), now);
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * 清理一个退役版本：仅当它已退役且宽限期已结束（{@code now >= graceDeadline}）时允许。
     * 与轮换共用同一把变更锁，前置条件在锁内对最新快照判定，保证清理针对的版本状态就是当前真实状态。
     *
     * <p>{@code preCommitAudit} 在状态发布（密钥材料移除）<b>之前</b>、且仍持锁时被调用：
     * 审计写不进去就抛异常，关键区直接退出、快照不切换，做到"状态变了必有记录，审计失败则状态不变"。
     *
     * <p>前置条件不满足时抛 {@link KeyVersionNotPurgeableException}；
     * 版本从未存在抛 {@link UnknownKeyVersionException}。
     */
    public PurgeOutcome purge(int version, java.util.function.Consumer<PurgeOutcome> preCommitAudit) {
        boolean acquired;
        try {
            acquired = rwLock.writeLock().tryLock(LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("清理等待被中断");
        }
        if (!acquired) {
            throw new RotationConflictException("已有密钥变更（轮换/清理）正在进行，本次并发清理被拒绝");
        }
        try {
            Snapshot before = snapshot.get();
            Instant now = Instant.now(clock);
            KeyVersion kv = before.versions().get(version);
            if (kv == null) {
                if (before.purged().containsKey(version)) {
                    throw new KeyVersionNotPurgeableException(
                            "密钥版本 v" + version + " 此前已被清理，不能重复清理");
                }
                throw new UnknownKeyVersionException("密钥版本不存在，无法清理: v" + version);
            }
            if (kv.isCurrent()) {
                throw new KeyVersionNotPurgeableException(
                        "v" + version + " 是当前版本，当前版本不允许清理，请先轮换");
            }
            if (kv.graceDeadline() != null && now.isBefore(kv.graceDeadline())) {
                throw new KeyVersionNotPurgeableException(
                        "旧密钥版本 v" + version + " 仍在宽限期内(deadline="
                                + kv.graceDeadline() + "，now=" + now + ")，宽限期结束前不许清理");
            }

            Map<Integer, KeyVersion> nextVersions = new java.util.HashMap<>(before.versions());
            KeyVersion removed = nextVersions.remove(version);
            Map<Integer, PurgedVersion> nextPurged = new java.util.HashMap<>(before.purged());
            PurgeOutcome outcome = new PurgeOutcome(version, now, removed.graceDeadline());
            nextPurged.put(version, new PurgedVersion(
                    version, removed.retiredAt(), removed.graceDeadline(), now));

            // 审计先于状态发布：此处抛异常则直接退出，快照保持不变（fail-closed）
            preCommitAudit.accept(outcome);

            // 唯一的状态发布点：移除材料与写入墓碑一次性整体发生
            snapshot.set(new Snapshot(Map.copyOf(nextVersions),
                    Map.copyOf(nextPurged), before.currentVersion()));
            return outcome;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * 在与轮换/清理<b>互斥</b>的读锁关键区内执行升级的提交动作（目标版本复核 → 审计 → 返回新密文）。
     *
     * <p>这是升级的线性化点：
     * <ul>
     *   <li>若目标版本在等待/进入关键区期间已被清理，{@code committer} 内的复核
     *       （{@link #requireReadableAtCommit}）会看到墓碑并抛
     *       {@link KeyVersionPurgedException}，
     *       整批被拒绝、不返回任何新密文；</li>
     *   <li>若目标版本在提交时仍存活（current 或宽限期内的 retired），提交顺利完成，
     *       返回的密文引用的就是返回那一刻真实存在且可读的版本。</li>
     * </ul>
     *
     * <p>耗时的解密/重加密必须发生在本方法之外（读锁不保护它们），因此批量升级的并行度不受影响；
     * 多个升级提交可同时共享读锁。等待写锁退场期间被中断或超时则按冲突明确拒绝（fail-closed）。
     *
     * @param targetVersion 升级在请求开始时锁定的目标版本
     * @param committer     提交回调（复核 + 审计 + 组装结果）；其异常原样上抛，锁一定被释放
     */
    public <T> T commitUpgrade(int targetVersion, Callable<T> committer) {
        boolean acquired;
        try {
            acquired = rwLock.readLock().tryLock(COMMIT_LOCK_WAIT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RotationConflictException("升级提交等待被中断");
        }
        if (!acquired) {
            throw new RotationConflictException(
                    "升级提交等待密钥变更关键区超时，fail-closed 拒绝，不返回任何新密文");
        }
        try {
            return committer.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("升级提交内部错误", e);
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /**
     * 升级提交时复核目标版本此刻仍可作为新密文的落脚版本。必须在
     * {@link #commitUpgrade} 的读锁关键区内调用。判定与读取路径一致且可解释：
     * 已清理 → {@code KEY_VERSION_PURGED}；从未存在 → {@code UNKNOWN_KEY_VERSION}；
     * 宽限期已结束 → {@code KEY_VERSION_GRACE_EXPIRED}；当前版本或宽限期内的退役版本 → 通过。
     */
    public KeyVersion requireReadableAtCommit(int targetVersion, Instant now) {
        KeyVersion kv = snapshot.get().versions().get(targetVersion);
        if (kv == null) {
            PurgedVersion tomb = snapshot.get().purged().get(targetVersion);
            if (tomb != null) {
                throw new KeyVersionPurgedException(
                        "升级锁定的目标版本 v" + targetVersion
                                + " 在提交前已被清理移出(purgedAt=" + tomb.purgedAt()
                                + ")，整批拒绝，不用其它当前版本顶替，不返回任何新密文");
            }
            throw new UnknownKeyVersionException(
                    "升级锁定的目标版本在提交时已不存在: v" + targetVersion);
        }
        if (!kv.isCurrent() && !kv.isWithinGrace(now)) {
            throw new KeyGraceExpiredException(
                    "升级锁定的目标版本 v" + targetVersion
                            + " 在提交时宽限期已结束(deadline=" + kv.graceDeadline()
                            + "，now=" + now + ")，整批拒绝，不返回任何新密文");
        }
        return kv;
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

    /** 取指定版本的清理墓碑；从未存在或仍存活均返回 empty（请先区分 {@link #findVersion}）。 */
    public Optional<PurgedVersion> findPurged(int version) {
        return Optional.ofNullable(snapshot.get().purged().get(version));
    }

    public List<KeyVersion> allVersions() {
        Snapshot s = snapshot.get();
        return s.versions().values().stream()
                .sorted(java.util.Comparator.comparingInt(KeyVersion::version))
                .collect(Collectors.toList());
    }

    /** 已被清理版本的墓碑列表（不含密钥材料），便于追溯。 */
    public List<PurgedVersion> purgedVersions() {
        Snapshot s = snapshot.get();
        return s.purged().values().stream()
                .sorted(java.util.Comparator.comparingInt(PurgedVersion::version))
                .collect(Collectors.toList());
    }

    /** 轮换输出。 */
    public record RotationOutcome(int previousVersion, int newVersion, Instant rotatedAt) {
    }
}
