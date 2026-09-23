package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Duration;
import java.time.Instant;

/** 轮换成功结论。 */
public record RotateResult(int previousVersion, int newVersion, Instant rotatedAt, Duration gracePeriod) {
}
