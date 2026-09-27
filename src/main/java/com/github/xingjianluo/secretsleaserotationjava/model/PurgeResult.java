package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/** 退役版本清理结论。 */
public record PurgeResult(int version, Instant purgedAt, Instant graceDeadline) {
}
