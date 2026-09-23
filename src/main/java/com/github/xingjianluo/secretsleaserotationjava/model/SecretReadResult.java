package com.github.xingjianluo.secretsleaserotationjava.model;

/** 敏感读取成功结论：明文 + 实际解密所用密钥版本 + 校验通过的租约。 */
public record SecretReadResult(String leaseId, String subject, String scope,
                               int keyVersion, String plaintext) {
}
