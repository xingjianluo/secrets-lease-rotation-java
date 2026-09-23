package com.github.xingjianluo.secretsleaserotationjava.support;

import com.github.xingjianluo.secretsleaserotationjava.clock.TimeSource;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 测试用可控时钟：初始固定在一个基准时刻，可精确前进以验证宽限期/过期边界。
 */
public class MutableTimeSource implements TimeSource {

    private final AtomicReference<Instant> now;

    public MutableTimeSource(Instant start) {
        this.now = new AtomicReference<>(start);
    }

    public static MutableTimeSource startAt(Instant start) {
        return new MutableTimeSource(start);
    }

    @Override
    public Instant now() {
        return now.get();
    }

    public void advance(Duration duration) {
        now.updateAndGet(t -> t.plus(duration));
    }

    public void set(Instant instant) {
        now.set(instant);
    }
}
