package com.github.xingjianluo.secretsleaserotationjava.crypto;

/**
 * 密文信封的解析视图：携带密钥版本与作用域前缀。
 * 线路格式：v&lt;版本号&gt;:&lt;作用域&gt;:&lt;Base64(iv||ciphertext+tag)&gt;
 */
public record Envelope(int version, String scope, byte[] ivAndCiphertext) {
}
