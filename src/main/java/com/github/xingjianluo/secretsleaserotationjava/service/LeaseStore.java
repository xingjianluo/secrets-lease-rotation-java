package com.github.xingjianluo.secretsleaserotationjava.service;

import com.github.xingjianluo.secretsleaserotationjava.model.Lease;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 租约库 + 主体登记表。
 * 主体必须先登记；租约按 leaseId 存取，所有集合操作线程安全。
 * 租约对象本身的撤销状态用 volatile 字段更新，读路径每次按 id 取出最新状态，
 * 不做跨请求/跨主体的结果缓存，因此并发读取不会串用不同主体的结果。
 */
@Component
public class LeaseStore {

    private final Set<String> subjects = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Lease> leases = new ConcurrentHashMap<>();

    /** 登记主体。幂等：重复登记不报错。 */
    public void registerSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject 不能为空");
        }
        subjects.add(subject);
    }

    public boolean isRegisteredSubject(String subject) {
        return subject != null && subjects.contains(subject);
    }

    public void put(Lease lease) {
        leases.put(lease.leaseId(), lease);
    }

    public Optional<Lease> find(String leaseId) {
        if (leaseId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(leases.get(leaseId));
    }

    public List<Lease> all() {
        return List.copyOf(leases.values());
    }
}
