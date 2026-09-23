package com.github.xingjianluo.secretsleaserotationjava.clock;

import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * 生产环境时间来源：直接读取系统 UTC 时间。
 */
@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public Instant now() {
        return Instant.now();
    }
}
