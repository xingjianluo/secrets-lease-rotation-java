package com.github.xingjianluo.secretsleaserotationjava.model;

import java.util.List;

/** 一批密文升级的整体结论：全有或全无，任一项失败则整批拒绝、不返回任何新密文。 */
public record UpgradeResult(String leaseId, String subject, String scope,
                            int targetVersion, List<UpgradeItemResult> items) {

    public int upgradedCount() {
        return items.size();
    }
}
