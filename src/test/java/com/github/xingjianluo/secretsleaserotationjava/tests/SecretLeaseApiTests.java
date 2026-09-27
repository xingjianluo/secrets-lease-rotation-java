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

    @Test
    void httpUpgradeAndPurgeReturnConsistentReasonAndStatus() throws Exception {
        postOk("/api/subjects", """
                {"subject":"alice"}""");
        MvcResult enc = postOk("/api/encrypt", """
                {"scope":"payroll","plaintext":"salary"}""");
        String v1Cipher = om.readTree(enc.getResponse().getContentAsString()).get("ciphertext").asText();
        MvcResult lease = postOk("/api/leases", """
                {"subject":"alice","scope":"payroll","ttl":"PT10M"}""");
        String leaseId = om.readTree(lease.getResponse().getContentAsString()).get("leaseId").asText();

        // 轮换 v1 -> v2，宽限期设长一点，保证 v1 仍可升级
        postOk("/api/keys/rotate", """
                {"gracePeriod":"PT24H"}""");

        // 单条升级 200，新密文落在 v2
        MvcResult up = postOk("/api/upgrade",
                "{\"leaseId\":\"" + leaseId + "\",\"ciphertext\":\"" + v1Cipher + "\"}");
        JsonNode upBody = om.readTree(up.getResponse().getContentAsString());
        log.info("HTTP 升级 200 source=v{} target=v{}",
                upBody.get("sourceVersion").asInt(), upBody.get("targetVersion").asInt());
        org.assertj.core.api.Assertions.assertThat(upBody.get("targetVersion").asInt()).isEqualTo(2);
        String v2Cipher = upBody.get("ciphertext").asText();

        // 升级后新密文可读，明文一致
        MvcResult readUp = postOk("/api/read",
                "{\"leaseId\":\"" + leaseId + "\",\"ciphertext\":\"" + v2Cipher + "\"}");
        org.assertj.core.api.Assertions.assertThat(
                om.readTree(readUp.getResponse().getContentAsString()).get("plaintext").asText())
                .isEqualTo("salary");

        // 批量升级 200
        MvcResult batch = postOk("/api/upgrade/batch",
                "{\"leaseId\":\"" + leaseId + "\",\"ciphertexts\":[\"" + v1Cipher + "\",\""
                        + v2Cipher + "\"]}");
        JsonNode batchBody = om.readTree(batch.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(batchBody.get("count").asInt()).isEqualTo(2);
        org.assertj.core.api.Assertions.assertThat(batchBody.get("targetVersion").asInt()).isEqualTo(2);

        // 宽限期未到清理 v1：412 KEY_VERSION_NOT_PURGEABLE
        assertDeny("/api/keys/purge", """
                {"version":1}""", 412, "KEY_VERSION_NOT_PURGEABLE");

        // 清理当前版本 v2：412
        assertDeny("/api/keys/purge", """
                {"version":2}""", 412, "KEY_VERSION_NOT_PURGEABLE");

        // 不存在版本：410 UNKNOWN_KEY_VERSION
        assertDeny("/api/keys/purge", """
                {"version":99}""", 410, "UNKNOWN_KEY_VERSION");

        // 把 v1 宽限期降为已结束：再轮换一次并推进时间不可行（时钟由服务端固定），
        // 这里改用 0 宽限期的一条链路验证"清理后读=410 KEY_VERSION_PURGED"。
        postOk("/api/subjects", """
                {"subject":"bob"}""");
        MvcResult bobEnc = postOk("/api/encrypt", """
                {"scope":"hr","plaintext":"hr-secret"}""");
        // 当前是 v2；先拿到一条 v2 密文，轮换 v2->v3（0 宽限）后清理 v2
        String v2HrCipher = om.readTree(bobEnc.getResponse().getContentAsString()).get("ciphertext").asText();
        MvcResult bobLease = postOk("/api/leases", """
                {"subject":"bob","scope":"hr","ttl":"PT10M"}""");
        String bobLeaseId = om.readTree(bobLease.getResponse().getContentAsString()).get("leaseId").asText();
        postOk("/api/keys/rotate", """
                {"gracePeriod":"PT0S"}""");
        // 0 宽限：v2 已可清理
        postOk("/api/keys/purge", """
                {"version":2}""");
        // 清理后再读 v2 密文：410 KEY_VERSION_PURGED，不拿当前版本顶替
        assertDeny("/api/read",
                "{\"leaseId\":\"" + bobLeaseId + "\",\"ciphertext\":\"" + v2HrCipher + "\"}",
                410, "KEY_VERSION_PURGED");
        // 清理后再升级 v2 密文：同样 410 KEY_VERSION_PURGED
        assertDeny("/api/upgrade",
                "{\"leaseId\":\"" + bobLeaseId + "\",\"ciphertext\":\"" + v2HrCipher + "\"}",
                410, "KEY_VERSION_PURGED");
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
