package com.github.xingjianluo.secretsleaserotationjava.exception;

import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;

/**
 * 升级提交阶段被明确拒绝：请求开始时锁定的目标当前版本，
 * 在这批密文处理期间已被新的轮换取代。整批拒绝、不吐出任何新密文，
 * 调用方应基于最新的当前版本重新发起升级（不会被悄悄改写目标版本）。
 */
public class UpgradeTargetSupersededException extends SecretLeaseException {
    public UpgradeTargetSupersededException(String message) {
        super(DenyReason.UPGRADE_TARGET_SUPERSEDED, message);
    }
}
