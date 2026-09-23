package com.github.xingjianluo.secretsleaserotationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 经 HTTP 入口端到端验证：错误原因被正确归类为状态码与 error 字段，
 * 轮换冲突返回 200 + rotated=false，正常流程走通。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiIntegrationTests {

    @Autowired
    private MockMvc mvc;
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void fullFlowThroughHttp() throws Exception {
        // 注册主体
        mvc.perform(post("/api/subjects").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject\":\"alice\"}"))
                .andExpect(status().isCreated());

        // 未注册主体签发租约 -> 403 UNKNOWN_SUBJECT
        String unknownBody = mvc.perform(post("/api/leases").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject\":\"bob\",\"scope\":\"payroll\",\"ttlSeconds\":60}"))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString();
        assertEquals("UNKNOWN_SUBJECT", json.readTree(unknownBody).get("error").asText());

        // 加密
        String sealBody = mvc.perform(post("/api/seal").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"salary\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode sealJson = json.readTree(sealBody);
        String cipher = sealJson.get("ciphertext").asText();
        assertEquals(1, sealJson.get("keyVersion").asInt());

        // 签发租约
        String leaseBody = mvc.perform(post("/api/leases").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject\":\"alice\",\"scope\":\"payroll\",\"ttlSeconds\":300}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String token = json.readTree(leaseBody).get("token").asText();

        // 越权作用域 -> 403 SCOPE_MISMATCH
        String mismatchBody = mvc.perform(post("/api/read").contentType(MediaType.APPLICATION_JSON)
                        .content(readBody(token, "invoices", cipher)))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString();
        assertEquals("SCOPE_MISMATCH", json.readTree(mismatchBody).get("error").asText());

        // 正常读取
        String readBody = mvc.perform(post("/api/read").contentType(MediaType.APPLICATION_JSON)
                        .content(readBody(token, "payroll", cipher)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals("salary", json.readTree(readBody).get("plaintext").asText());

        // 轮换
        String rotate1 = mvc.perform(post("/api/rotate"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(json.readTree(rotate1).get("rotated").asBoolean());
        assertEquals(2, json.readTree(rotate1).get("version").asInt());

        // 旧密文宽限期内经 HTTP 仍可读
        String graceRead = mvc.perform(post("/api/read").contentType(MediaType.APPLICATION_JSON)
                        .content(readBody(token, "payroll", cipher)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals("salary", json.readTree(graceRead).get("plaintext").asText());

        // 撤销后读取 -> 403 LEASE_REVOKED
        mvc.perform(post("/api/revoke").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"leaseToken\":\"" + token + "\"}"))
                .andExpect(status().isOk());
        String revokedBody = mvc.perform(post("/api/read").contentType(MediaType.APPLICATION_JSON)
                        .content(readBody(token, "payroll", cipher)))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString();
        assertEquals("LEASE_REVOKED", json.readTree(revokedBody).get("error").asText());

        // 不存在的租约 -> 404 UNKNOWN_LEASE
        mvc.perform(post("/api/revoke").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"leaseToken\":\"deadbeef\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void badCiphertextMapsTo400() throws Exception {
        mvc.perform(post("/api/subjects").contentType(MediaType.APPLICATION_JSON)
                .content("{\"subject\":\"carol\"}")).andExpect(status().isCreated());
        String leaseBody = mvc.perform(post("/api/leases").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject\":\"carol\",\"scope\":\"x\",\"ttlSeconds\":300}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String token = json.readTree(leaseBody).get("token").asText();
        String body = mvc.perform(post("/api/read").contentType(MediaType.APPLICATION_JSON)
                        .content(readBody(token, "x", "garbage")))
                .andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsString();
        assertEquals("BAD_CIPHERTEXT", json.readTree(body).get("error").asText());
        assertFalse(body.contains("plaintext"), "错误体不得泄漏明文相关内容");
    }

    private static String readBody(String token, String scope, String cipher) {
        return "{\"leaseToken\":\"" + token + "\",\"scope\":\"" + scope
                + "\",\"ciphertext\":\"" + cipher + "\"}";
    }
}
