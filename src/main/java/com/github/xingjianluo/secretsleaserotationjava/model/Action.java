package com.github.xingjianluo.secretsleaserotationjava.model;

/** 需要留痕的动作类型。 */
public enum Action {
    ROTATE,
    ISSUE_LEASE,
    READ_SECRET,
    REVOKE_LEASE,
    ENCRYPT_SECRET,
    /** 旧版本密文重新加密为当前版本密文。 */
    UPGRADE_CIPHERTEXT,
    /** 清理（移出）已过宽限期的退役密钥版本。 */
    PURGE_KEY_VERSION
}
