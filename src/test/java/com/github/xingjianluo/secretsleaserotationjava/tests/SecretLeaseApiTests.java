package com.github.xingjianluo.secretsleaserotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.junit.jupiter.api.BeforeEach;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * REST 入口一致性：服务门面的可区分拒绝原因，经 HTTP 必须映射为固定状态码与同一 reason。
 */
@SpringBootTest
class SecretLeaseApiTests {

    private static final Logger log = LoggerFactory.getLogger(SecretLeaseApiTests.class);
    private final ObjectMapper om = new ObjectMapper();

    @Autowired
    private WebApplicationContext wac;
    private MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(wac).build();
    }

    @Test
    void httpEntryReturnsConsistentReasonAndStatus() throws Exception {
        postOk("/api/subjects", """
                {"subject":"alice"}""");

        MvcResult enc = postOk("/api/encrypt", """
                {"scope":"payroll","plaintext":"salary"}""");
        String ciphertext = om.readTree(enc.getResponse().getContentAsString()).get("ciphertext").asText();

        // 成功签发并读取
        MvcResult lease = postOk("/api/leases", """
                {"subject":"alice","scope":"payroll","ttl":"PT10M"}""");
        String leaseId = om.readTree(lease.getResponse().getContentAsString()).get("leaseId").asText();
        MvcResult ok = postOk("/api/read",
                "{\"leaseId\":\"" + leaseId + "\",\"ciphertext\":\"" + ciphertext + "\"}");
        JsonNode okBody = om.readTree(ok.getResponse().getContentAsString());
        log.info("HTTP 读取成功 200 plaintext={} keyVersion={}",
                okBody.get("plaintext").asText(), okBody.get("keyVersion").asInt());

        // 轮换成功 200
        postOk("/api/keys/rotate", """
                {"gracePeriod":"PT0S"}""");

        // 宽限期为 0：旧密文经 HTTP 必须 410 + KEY_VERSION_GRACE_EXPIRED，而非静默降级
        assertDeny("/api/read",
                "{\"leaseId\":\"" + leaseId + "\",\"ciphertext\":\"" + ciphertext + "\"}",
                410, "KEY_VERSION_GRACE_EXPIRED");

        // 未知租约 404
        assertDeny("/api/read",
                "{\"leaseId\":\"missing\",\"ciphertext\":\"" + ciphertext + "\"}",
                404, "UNKNOWN_LEASE");

        // 未知主体签发 404
        assertDeny("/api/leases",
                """
                {"subject":"ghost","scope":"payroll","ttl":"PT1M"}""",
                404, "UNKNOWN_SUBJECT");
    }

    private void assertDeny(String url, String body, int httpStatus, String reason) throws Exception {
        MvcResult r = mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().is(httpStatus))
                .andReturn();
        JsonNode json = om.readTree(r.getResponse().getContentAsString());
        String actualReason = json.get("reason") == null ? "null" : json.get("reason").asText();
        log.info("HTTP 拒绝 {} -> {} reason={}（期望 {}）msg={}",
                url, httpStatus, actualReason, reason, json.get("message").asText());
        org.assertj.core.api.Assertions.assertThat(actualReason).isEqualTo(reason);
    }

    private MvcResult postOk(String url, String body) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().is2xxSuccessful())
                .andReturn();
    }
}
