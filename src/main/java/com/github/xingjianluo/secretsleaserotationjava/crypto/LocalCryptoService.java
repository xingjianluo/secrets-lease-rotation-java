package com.github.xingjianluo.secretsleaserotationjava.crypto;

import com.github.xingjianluo.secretsleaserotationjava.exception.UnknownKeyVersionException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 本地密钥材料上的 AES-256-GCM 加解密。密钥版本与作用域以明文前缀写入密文，
 * 因此读取方在解密前即可判定版本与作用域，版本过期时不会去尝试解密（不静默降级）。
 *
 * <p>线路格式：{@code v<版本号>:<作用域>:<Base64(iv(12B) || ciphertext+tag(128B))>}
 */
@Service
public class LocalCryptoService {

    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final String KEY_ALG = "AES";
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";
    private static final String PREFIX = "v";
    private static final String SEPARATOR = ":";

    private final SecureRandom random = new SecureRandom();

    /** 生成新的 256 位本地密钥材料。 */
    public byte[] generateKey() {
        byte[] key = new byte[32];
        random.nextBytes(key);
        return key;
    }

    /** 加密为线路格式字符串。 */
    public String encrypt(int version, String scope, byte[] key, String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, KEY_ALG),
                    new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(utf8(plaintext));
            byte[] combined = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ct, 0, combined, iv.length, ct.length);
            return PREFIX + version + SEPARATOR + scope + SEPARATOR + b64(combined);
        } catch (Exception e) {
            throw new IllegalStateException("加密失败", e);
        }
    }

    /** 解密（GCM 同时校验完整性，密钥错误或被篡改会抛异常）。 */
    public String decrypt(byte[] key, byte[] ivAndCiphertext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            byte[] ct = new byte[ivAndCiphertext.length - IV_LENGTH];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LENGTH);
            System.arraycopy(ivAndCiphertext, IV_LENGTH, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, KEY_ALG),
                    new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new UnknownKeyVersionException("密文完整性校验或解密失败", e);
        }
    }

    /**
     * 解析线路格式。格式非法 / 版本号非法时一律按"未知版本"拒绝，
     * 避免伪造密文被当作其它类型处理。
     */
    public Envelope parse(String ciphertext) {
        if (ciphertext == null) {
            throw new UnknownKeyVersionException("密文为空");
        }
        String s = ciphertext;
        if (!s.startsWith(PREFIX)) {
            throw new UnknownKeyVersionException("密文缺少版本前缀");
        }
        // 作用域本身不允许包含分隔符，故按分隔符切三段
        String[] parts = s.substring(PREFIX.length()).split(SEPARATOR, 3);
        if (parts.length != 3) {
            throw new UnknownKeyVersionException("密文格式段数不为 3");
        }
        final int version;
        try {
            version = Integer.parseInt(parts[0]);
        } catch (NumberFormatException e) {
            throw new UnknownKeyVersionException("密文版本号非法: " + parts[0]);
        }
        if (version <= 0) {
            throw new UnknownKeyVersionException("密文版本号必须为正数: " + version);
        }
        String scope = parts[1];
        if (scope.isBlank()) {
            throw new UnknownKeyVersionException("密文作用域为空");
        }
        final byte[] combined;
        try {
            combined = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new UnknownKeyVersionException("密文体不是合法 Base64", e);
        }
        if (combined.length <= IV_LENGTH) {
            throw new UnknownKeyVersionException("密文体长度不足");
        }
        return new Envelope(version, scope, combined);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
