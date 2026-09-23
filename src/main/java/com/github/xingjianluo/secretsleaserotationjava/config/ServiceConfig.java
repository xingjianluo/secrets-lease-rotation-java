package com.github.xingjianluo.secretsleaserotationjava.config;

import com.github.xingjianluo.secretsleaserotationjava.clock.TimeSource;
import com.github.xingjianluo.secretsleaserotationjava.crypto.LocalKeyManager;
import com.github.xingjianluo.secretsleaserotationjava.lease.LeaseStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 非组件类型的 Spring 装配：密钥管理器、租约存储均为有状态单例，
 * 宽限期等策略来自 {@link AppProperties}。
 */
@Configuration
public class ServiceConfig {

    @Bean
    public LocalKeyManager localKeyManager(TimeSource clock, AppProperties properties) {
        return new LocalKeyManager(clock, properties.gracePeriod());
    }

    @Bean
    public LeaseStore leaseStore() {
        return new LeaseStore();
    }
}
