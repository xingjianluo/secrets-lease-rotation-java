package com.github.xingjianluo.secretsleaserotationjava.api.dto;

import java.time.Duration;

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

    /** 单份密文升级请求。 */
    public record UpgradeRequest(String leaseId, String ciphertext) {
    }

    /** 一批密文升级请求（整批全有或全无）。 */
    public record UpgradeBatchRequest(String leaseId, java.util.List<String> ciphertexts) {
    }

    /** 退役版本清理请求。 */
    public record PurgeRequest(Integer version) {
    }
}
