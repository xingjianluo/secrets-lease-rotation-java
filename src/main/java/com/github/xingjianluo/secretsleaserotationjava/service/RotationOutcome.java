package com.github.xingjianluo.secretsleaserotationjava.service;

/**
 * 轮换结果：成功（携带新版本号）或可区分的并发冲突拒绝。
 */
public sealed interface RotationOutcome
        permits com.github.xingjianluo.secretsleaserotationjava.service.RotationOutcome.Rotated,
                com.github.xingjianluo.secretsleaserotationjava.service.RotationOutcome.Conflict {

    record Rotated(int newVersion) implements RotationOutcome {
    }

    record Conflict(int currentVersion) implements RotationOutcome {
    }
}
