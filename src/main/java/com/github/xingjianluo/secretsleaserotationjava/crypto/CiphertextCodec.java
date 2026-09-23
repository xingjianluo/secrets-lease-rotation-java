package com.github.xingjianluo.secretsleaserotationjava.crypto;

import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import java.util.Base64;

/**
 * 受管密文在各入口之间传输的文本编码，固定为：
 * <pre>mlcv1:&lt;keyVersion&gt;:&lt;base64(iv)&gt;:&lt;base64(ciphertext)></pre>
 * 前缀 mlcv1 标识 managed-local-ciphertext v1，任何解析失败一律归类为 BAD_CIPHERTEXT。
 */
public final class CiphertextCodec {

    private static final String PREFIX = "mlcv1";

    private CiphertextCodec() {
    }

    public static String encode(ManagedCiphertext ciphertext) {
        Base64.Encoder encoder = Base64.getEncoder();
        return PREFIX + ":" + ciphertext.keyVersion() + ":"
                + encoder.encodeToString(ciphertext.iv()) + ":"
                + encoder.encodeToString(ciphertext.bytes());
    }

    public static ManagedCiphertext decode(String text) {
        if (text == null) {
            throw new ServiceException(Reason.BAD_CIPHERTEXT, "ciphertext is absent");
        }
        String[] parts = text.strip().split(":", -1);
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            throw new ServiceException(Reason.BAD_CIPHERTEXT,
                    "ciphertext must have format " + PREFIX + ":<version>:<iv>:<data>");
        }
        try {
            int version = Integer.parseInt(parts[1]);
            if (version < 1) {
                throw new ServiceException(Reason.BAD_CIPHERTEXT, "key version must be positive");
            }
            byte[] iv = Base64.getDecoder().decode(parts[2]);
            byte[] data = Base64.getDecoder().decode(parts[3]);
            return new ManagedCiphertext(version, iv, data);
        } catch (IllegalArgumentException e) {
            throw new ServiceException(Reason.BAD_CIPHERTEXT, "ciphertext contains invalid base64 or version", e);
        }
    }
}
