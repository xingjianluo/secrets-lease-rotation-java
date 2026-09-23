package com.github.xingjianluo.secretsleaserotationjava.web;

import java.time.Instant;

/**
 * HTTP 入口的请求/响应载荷定义（全部不可变）。
 */
public final class ApiDtos {

    private ApiDtos() {
    }

    public record RegisterSubjectRequest(String subject) {
    }

    public record SealRequest(String plaintext) {
    }

    public record CiphertextResponse(String ciphertext, int keyVersion) {
    }

    public record IssueRequest(String subject, String scope, Long ttlSeconds) {
    }

    public record LeaseResponse(String token, String subject, String scope,
                                Instant issuedAt, Instant expiresAt, int keyVersion) {
    }

    public record ReadRequest(String leaseToken, String scope, String ciphertext) {
    }

    public record ReadResponse(String plaintext, int keyVersionUsed) {
    }

    public record RotateResponse(boolean rotated, int version) {
    }

    public record RevokeRequest(String leaseToken) {
    }

    public record ErrorResponse(String error, String message) {
    }
}
