package com.github.xingjianluo.secretsleaserotationjava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 注入系统 UTC 时钟；测试可替换为可控时钟以精确验证宽限期边界。 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
