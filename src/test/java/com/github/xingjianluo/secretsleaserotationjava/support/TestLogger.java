package com.github.xingjianluo.secretsleaserotationjava.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 单测日志助手：每个用例打印输入条件与最终判定依据，便于人工复核结论可解释性。
 */
public final class TestLogger {

    private static final Logger LOG = LoggerFactory.getLogger("SCENARIO");

    private TestLogger() {
    }

    public static void given(String scenario, String... facts) {
        LOG.info("[{}] 输入条件:", scenario);
        for (String fact : facts) {
            LOG.info("[{}]   - {}", scenario, fact);
        }
    }

    public static void decided(String scenario, String decision) {
        LOG.info("[{}] 判定依据/结果: {}", scenario, decision);
    }
}
