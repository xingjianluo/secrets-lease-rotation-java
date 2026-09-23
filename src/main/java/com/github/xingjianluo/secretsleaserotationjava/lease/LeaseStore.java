package com.github.xingjianluo.secretsleaserotationjava.lease;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 主体注册表与租约存储（内存实现，模拟受管服务端状态）。
 * 所有访问均为线程安全的，保证并发读取之间不会串用彼此的结果：
 * 租约记录不可变，撤销通过 {@code compute} 原子替换。
 */
public class LeaseStore {

    private final Set<String> subjects = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Lease> leases = new ConcurrentHashMap<>();

    /** 注册一个合法主体；重复注册幂等。 */
    public void registerSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        subjects.add(subject);
    }

    public boolean subjectExists(String subject) {
        return subject != null && subjects.contains(subject);
    }

    /** 保存一份新签发的租约；token 冲突时直接抛出（生成方使用安全随机数，实际不会发生）。 */
    public void put(Lease lease) {
        Lease previous = leases.putIfAbsent(lease.token(), lease);
        if (previous != null) {
            throw new IllegalStateException("duplicate lease token: " + lease.token());
        }
    }

    public Optional<Lease> find(String token) {
        if (token == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(leases.get(token));
    }

    /**
     * 原子撤销租约：
     * 不存在返回 empty；已撤销原样返回；否则替换为撤销副本并返回。
     *
     * @param at 撤销时刻，由服务层统一从 {@code TimeSource} 取得
     */
    public Optional<Lease> revoke(String token, Instant at) {
        if (token == null) {
            return Optional.empty();
        }
        leases.computeIfPresent(token, (t, lease) -> lease.isRevoked() ? lease : lease.revoked(at));
        return Optional.ofNullable(leases.get(token));
    }

    /** 测试支持：查看当前租约数量。 */
    public int size() {
        return leases.size();
    }
}
