package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/** 租约签发成功结论。 */
public record LeaseIssueResult(String leaseId, String subject, String scope,
                               Instant issuedAt, Instant expiresAt) {
}
