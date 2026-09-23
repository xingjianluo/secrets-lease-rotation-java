package com.github.xingjianluo.secretsleaserotationjava.service;

import java.time.Instant;

/**
 * 签发成功后返回给调用方的租约视图。
 */
public record LeaseView(String token,
                        String subject,
                        String scope,
                        Instant issuedAt,
                        Instant expiresAt,
                        int keyVersion) {
}
