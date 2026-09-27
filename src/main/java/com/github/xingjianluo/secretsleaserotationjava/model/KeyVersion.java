package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/**
 * 一个受管密钥版本（不可变值对象）。本地用随机字节模拟受管密钥材料。
 * current 版本可加解密；retired 版本仅在其宽限期截止前可解密。
 *
 * <p>轮换不就地修改对象，而是通过 {@link #retiredCopy} 生成退役副本，
 * 与新版本一起放进不可变快照原子发布，杜绝轮换中间状态被观察到。
 */
public final class KeyVersion {

    private final int version;
    private final byte[] secret;
    private final Instant createdAt;
    private final boolean current;
    private final Instant retiredAt;
    private final Instant graceDeadline;
    private final boolean purged;
    private final Instant purgedAt;

    public KeyVersion(int version, byte[] secret, Instant createdAt, boolean current) {
        this(version, secret, createdAt, current, null, null, false, null);
    }

    private KeyVersion(int version, byte[] secret, Instant createdAt, boolean current,
                       Instant retiredAt, Instant graceDeadline, boolean purged, Instant purgedAt) {
        this.version = version;
        this.secret = secret;
        this.createdAt = createdAt;
        this.current = current;
        this.retiredAt = retiredAt;
        this.graceDeadline = graceDeadline;
        this.purged = purged;
        this.purgedAt = purgedAt;
    }

    public int version() { return version; }
    public byte[] secret() { return secret; }
    public Instant createdAt() { return createdAt; }
    public boolean isCurrent() { return current; }
    public Instant retiredAt() { return retiredAt; }
    public Instant graceDeadline() { return graceDeadline; }
    public boolean isPurged() { return purged; }
    public Instant purgedAt() { return purgedAt; }

    /** 生成一个内容相同但已退役、带宽限期截止时刻的副本。 */
    public KeyVersion retiredCopy(Instant now, Instant deadline) {
        return new KeyVersion(version, secret, createdAt, false, now, deadline, false, null);
    }

    /** 生成一个“已清理”墓碑副本：密钥材料不再可用，仅保留可解释的元数据。 */
    public KeyVersion purgedCopy(Instant now) {
        return new KeyVersion(version, null, createdAt, false, retiredAt, graceDeadline, true, now);
    }

    /**
     * 当前时刻是否仍处于宽限期内（可解旧密文）。
     * 只有已退役版本才有宽限期概念；边界时刻 now == deadline 视为宽限结束（拒绝）。
     */
    public boolean isWithinGrace(Instant now) {
        return !current && graceDeadline != null && now.isBefore(graceDeadline);
    }
}
