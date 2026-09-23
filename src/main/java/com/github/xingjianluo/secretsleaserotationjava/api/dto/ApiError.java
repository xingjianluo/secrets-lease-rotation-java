package com.github.xingjianluo.secretsleaserotationjava.api.dto;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

import java.time.Instant;

/** 统一错误响应体：错误必须被归类为某个可区分 {@link DenyReason}。 */
public record ApiError(Instant at, DenyReason reason, String message) {
}
