package com.github.xingjianluo.secretsleaserotationjava.api;

import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.EncryptRequest;
import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.IssueLeaseRequest;
import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.ReadRequest;
import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.RegisterSubjectRequest;
import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.RevokeRequest;
import com.github.xingjianluo.secretsleaserotationjava.api.dto.Requests.RotateRequest;
import com.github.xingjianluo.secretsleaserotationjava.model.EncryptResult;
import com.github.xingjianluo.secretsleaserotationjava.model.LeaseIssueResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RevokeResult;
import com.github.xingjianluo.secretsleaserotationjava.model.RotateResult;
import com.github.xingjianluo.secretsleaserotationjava.model.SecretReadResult;
import com.github.xingjianluo.secretsleaserotationjava.service.SecretLeaseService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 密钥托管 / 租约访问的 REST 入口。仅做参数编排，
 * 判定与审计全部在 {@link SecretLeaseService} 内完成，保证入口结论一致。
 */
@RestController
@RequestMapping("/api")
public class SecretLeaseController {

    private final SecretLeaseService service;

    public SecretLeaseController(SecretLeaseService service) {
        this.service = service;
    }

    @PostMapping("/subjects")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> registerSubject(@RequestBody RegisterSubjectRequest req) {
        service.registerSubject(req.subject());
        return Map.of("registered", true, "subject", req.subject());
    }

    @PostMapping("/encrypt")
    public EncryptResult encrypt(@RequestBody EncryptRequest req) {
        return service.encrypt(req.scope(), req.plaintext());
    }

    /** 无请求体或 gracePeriod 缺省时使用门面默认宽限期。 */
    @PostMapping("/keys/rotate")
    public RotateResult rotate(@RequestBody(required = false) RotateRequest req) {
        return service.rotate(req == null ? null : req.gracePeriod());
    }

    @PostMapping("/leases")
    @ResponseStatus(HttpStatus.CREATED)
    public LeaseIssueResult issueLease(@RequestBody IssueLeaseRequest req) {
        return service.issueLease(req.subject(), req.scope(), req.ttl());
    }

    @PostMapping("/read")
    public SecretReadResult read(@RequestBody ReadRequest req) {
        return service.read(req.leaseId(), req.ciphertext());
    }

    @PostMapping("/leases/revoke")
    public RevokeResult revoke(@RequestBody RevokeRequest req) {
        return service.revoke(req.leaseId());
    }
}
