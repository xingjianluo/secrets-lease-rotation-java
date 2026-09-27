package com.github.xingjianluo.secretsleaserotationjava.model;

/** 需要留痕的动作类型。 */
public enum Action {
    ROTATE,
    ISSUE_LEASE,
    READ_SECRET,
    REVOKE_LEASE,
    ENCRYPT_SECRET,
    /** 持有效租约把旧版本密文重新加密为当前版本（单条或一批，各记一条）。 */
    UPGRADE_SECRET,
    /** 清理一个宽限期已结束的退役版本。 */
    PURGE_KEY_VERSION
}
