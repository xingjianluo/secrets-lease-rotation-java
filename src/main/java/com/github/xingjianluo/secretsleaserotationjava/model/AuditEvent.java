package com.github.xingjianluo.secretsleaserotationjava.model;

import java.time.Instant;

/**
 * 一条不可变审计记录，关联主体、作用域、密钥版本与结果。
 * result 形如 "SUCCESS" 或 "DENIED:<reason>"。
 */
public record AuditEvent(Instant at, Action action, String subject, String scope,
                        Integer keyVersion, String leaseId, String result, String detail) {
}
