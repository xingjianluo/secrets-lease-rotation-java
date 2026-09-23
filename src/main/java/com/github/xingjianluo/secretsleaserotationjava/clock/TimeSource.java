package com.github.xingjianluo.secretsleaserotationjava.clock;

import java.time.Instant;

/**
 * 可替换的时间来源，生产环境使用系统时钟，测试中可注入可控时钟以验证宽限期与过期边界。
 */
public interface TimeSource {
    Instant now();
}
