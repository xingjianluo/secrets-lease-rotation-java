package com.github.xingjianluo.secretsleaserotationjava.web;

import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import com.github.xingjianluo.secretsleaserotationjava.service.LeaseView;
import com.github.xingjianluo.secretsleaserotationjava.service.ReadOutcome;
import com.github.xingjianluo.secretsleaserotationjava.service.RotationOutcome;
import com.github.xingjianluo.secretsleaserotationjava.service.SecretService;
import java.time.Duration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 各操作的 HTTP 入口；所有判定仍由 {@link SecretService} 统一给出，
 * 控制器只负责把统一的结果模型翻译成 HTTP 表达，保证入口之间结论一致。
 */
@RestController
@RequestMapping("/api")
public class SecretController {

    private final SecretService service;

    public SecretController(SecretService service) {
        this.service = service;
    }

    @PostMapping("/subjects")
    public ResponseEntity<String> registerSubject(@RequestBody ApiDtos.RegisterSubjectRequest request) {
        service.registerSubject(request.subject());
        return ResponseEntity.status(HttpStatus.CREATED).body("registered");
    }

    @PostMapping("/seal")
    public ApiDtos.CiphertextResponse seal(@RequestBody ApiDtos.SealRequest request) {
        return new ApiDtos.CiphertextResponse(service.seal(request.plaintext()),
                service.currentKeyVersion());
    }

    @PostMapping("/leases")
    public ResponseEntity<ApiDtos.LeaseResponse> issue(@RequestBody ApiDtos.IssueRequest request) {
        Duration ttl = request.ttlSeconds() == null ? null : Duration.ofSeconds(request.ttlSeconds());
        LeaseView view = service.issueLease(request.subject(), request.scope(), ttl);
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(view));
    }

    @PostMapping("/read")
    public ApiDtos.ReadResponse read(@RequestBody ApiDtos.ReadRequest request) {
        ReadOutcome outcome = service.read(request.leaseToken(), request.scope(), request.ciphertext());
        if (outcome instanceof ReadOutcome.Denied denied) {
            // 服务已完成判定与留痕，此处仅把可区分原因交给统一异常映射。
            throw new ServiceException(denied.reason(), denied.message());
        }
        ReadOutcome.Success success = (ReadOutcome.Success) outcome;
        return new ApiDtos.ReadResponse(success.plaintext(), success.keyVersionUsed());
    }

    @PostMapping("/rotate")
    public ResponseEntity<ApiDtos.RotateResponse> rotate() {
        RotationOutcome outcome = service.rotate();
        if (outcome instanceof RotationOutcome.Rotated rotated) {
            return ResponseEntity.ok(new ApiDtos.RotateResponse(true, rotated.newVersion()));
        }
        // 并发冲突以 409 + rotated=false 可区分地拒绝，调用方不会误判为成功轮换。
        RotationOutcome.Conflict conflict = (RotationOutcome.Conflict) outcome;
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiDtos.RotateResponse(false, conflict.currentVersion()));
    }

    @PostMapping("/revoke")
    public String revoke(@RequestBody ApiDtos.RevokeRequest request) {
        service.revoke(request.leaseToken());
        return "revoked";
    }

    private ApiDtos.LeaseResponse toResponse(LeaseView view) {
        return new ApiDtos.LeaseResponse(view.token(), view.subject(), view.scope(),
                view.issuedAt(), view.expiresAt(), view.keyVersion());
    }
}
