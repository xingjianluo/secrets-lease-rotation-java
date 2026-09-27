package com.github.xingjianluo.secretsleaserotationjava.api.dto;

import java.time.Duration;
import java.util.List;

/** REST 请求 DTO 集合。 */
public final class Requests {

    private Requests() {
    }

    public record RegisterSubjectRequest(String subject) {
    }

    public record EncryptRequest(String scope, String plaintext) {
    }

    public record RotateRequest(Duration gracePeriod) {
    }

    public record IssueLeaseRequest(String subject, String scope, Duration ttl) {
    }

    public record ReadRequest(String leaseId, String ciphertext) {
    }

    public record RevokeRequest(String leaseId) {
    }

    /** 升级单条密文到当前版本。 */
    public record UpgradeRequest(String leaseId, String ciphertext) {
    }

    /** 批量升级：整批全成或整批被拒，绝不返回部分新密文。 */
    public record UpgradeBatchRequest(String leaseId, List<String> ciphertexts) {
    }

    /** 清理一个宽限期已结束的退役版本。 */
    public record PurgeRequest(Integer version) {
    }
}

