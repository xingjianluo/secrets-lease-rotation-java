package com.github.xingjianluo.secretsleaserotationjava.model;

/** 加密成功结论：密文携带版本前缀与作用域。 */
public record EncryptResult(String scope, int keyVersion, String ciphertext) {
}
