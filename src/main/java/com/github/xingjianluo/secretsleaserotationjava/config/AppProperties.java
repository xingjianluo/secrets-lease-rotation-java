package com.github.xingjianluo.secretsleaserotationjava.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 应用配置：
 * <ul>
 *   <li>gracePeriod：密钥轮换后旧版本密文仍允许解密的宽限期；</li>
 *   <li>defaultLeaseTtl：签发租约时未显式指定 TTL 所采用的默认有效期。</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(Duration gracePeriod, Duration defaultLeaseTtl) {
}
