package com.github.xingjianluo.secretsleaserotationjava.service;

/**
 * 一次敏感读取的结果（密封类型，调用方可显式区分成功与各类拒绝）。
 */
public sealed interface ReadOutcome permits ReadOutcome.Success, ReadOutcome.Denied {

    record Success(String plaintext, int keyVersionUsed) implements ReadOutcome {
    }

    record Denied(com.github.xingjianluo.secretsleaserotationjava.error.Reason reason,
                  String message) implements ReadOutcome {
    }
}
