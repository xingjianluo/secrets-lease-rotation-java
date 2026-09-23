package com.github.xingjianluo.secretsleaserotationjava.crypto;

import java.time.Instant;
import javax.crypto.SecretKey;

/**
 * 一个受管密钥版本：版本号从 1 开始单调递增，轮换即引入新版本。
 */
public record KeyMaterial(int version, SecretKey key, Instant createdAt) {
}
