package com.github.xingjianluo.secretsleaserotationjava.model;

/** 单份密文升级结论：保持原作用域，密文落到当前密钥版本。 */
public record UpgradeItemResult(String scope, int sourceVersion, int targetVersion,
                                String sourceCiphertext, String ciphertext) {
}
