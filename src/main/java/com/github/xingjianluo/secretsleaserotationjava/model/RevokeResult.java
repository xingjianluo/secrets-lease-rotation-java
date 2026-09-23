package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/** 撤销成功结论。 */
public record RevokeResult(String leaseId, Instant revokedAt) {
}
