package com.github.xingjianluo.secretsleaserotationjava.model;

/**
 * 单条密文升级成功结论：旧版本密文被重新加密为当前版本。
 * 升级前后明文与作用域完全一致，新密文可用同一个有效租约读取且落在新版本上。
 */
public record UpgradeResult(String leaseId, String scope,
                            int sourceVersion, int targetVersion, String ciphertext) {
}
