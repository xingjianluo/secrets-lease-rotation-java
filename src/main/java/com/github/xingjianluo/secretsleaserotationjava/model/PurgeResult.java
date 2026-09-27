package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/**
 * 清理退役版本成功结论：该版本密钥材料已移出托管库。
 *
 * @param version        被清理的版本号
 * @param purgedAt       清理时刻
 * @param graceDeadline  该版本原本的宽限截止时刻（用于证明清理发生在宽限期结束之后）
 */
public record PurgeResult(int version, Instant purgedAt, Instant graceDeadline) {
}
