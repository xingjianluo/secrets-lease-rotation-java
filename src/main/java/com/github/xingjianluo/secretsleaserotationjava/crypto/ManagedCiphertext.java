package com.github.xingjianluo.secretsleaserotationjava.crypto;

/**
 * 受管密文：记录加密时使用的密钥版本以及 AES-GCM 的 IV 与密文（含认证标签）。
 */
public record ManagedCiphertext(int keyVersion, byte[] iv, byte[] bytes) {
}
