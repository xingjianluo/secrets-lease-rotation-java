package com.github.xingjianluo.secretsleaserotationjava.model;

/** 需要留痕的动作类型。 */
public enum Action {
    ROTATE,
    ISSUE_LEASE,
    READ_SECRET,
    REVOKE_LEASE,
    ENCRYPT_SECRET
}
