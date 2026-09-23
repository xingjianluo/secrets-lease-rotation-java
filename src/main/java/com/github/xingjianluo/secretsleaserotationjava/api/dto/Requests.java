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
}
