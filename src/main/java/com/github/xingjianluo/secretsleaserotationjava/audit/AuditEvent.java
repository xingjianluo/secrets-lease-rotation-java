package com.github.xingjianluo.secretsleaserotationjava.audit;

import java.time.Instant;

/**
 * 一条不可变审计记录：必须关联主体、作用域、密钥版本（无法确定时为 -1）与判定结果。
 */
public record AuditEvent(Instant at,
                         AuditAction action,
                         String subject,
                         String scope,
                         int keyVersion,
                         AuditResult result,
                         String detail) {
}
