package com.github.xingjianluo.secretsleaserotationjava.api;

import com.github.xingjianluo.secretsleaserotationjava.api.dto.ApiError;
import com.github.xingjianluo.secretsleaserotationjava.exception.SecretLeaseException;
import com.github.xingjianluo.secretsleaserotationjava.model.DenyReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Clock;
import java.time.Instant;

/**
 * 把领域异常映射为一致的 HTTP 错误响应。错误结论只取决于 {@link DenyReason}，
 * 与"从服务门面还是从 REST 进入"无关，保证跨入口一致。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Clock clock;

    public GlobalExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(SecretLeaseException.class)
    public ResponseEntity<ApiError> handle(SecretLeaseException ex) {
        return ResponseEntity.status(statusFor(ex.reason()))
                .body(new ApiError(Instant.now(clock), ex.reason(), ex.getMessage()));
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<ApiError> handleBadRequest(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError(Instant.now(clock), null, ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError(Instant.now(clock), null,
                        "未预期错误: " + ex.getClass().getSimpleName() + ": " + ex.getMessage()));
    }

    /** 可区分原因到 HTTP 语义的固定映射。 */
    private HttpStatus statusFor(DenyReason reason) {
        return switch (reason) {
            case ROTATION_IN_PROGRESS -> HttpStatus.CONFLICT;                 // 409
            case UNKNOWN_KEY_VERSION, KEY_VERSION_GRACE_EXPIRED ->
                    HttpStatus.GONE;                                          // 410 版本不可用
            case UNKNOWN_SUBJECT, UNKNOWN_LEASE -> HttpStatus.NOT_FOUND;      // 404
            case LEASE_EXPIRED, LEASE_REVOKED -> HttpStatus.FORBIDDEN;        // 403
            case SCOPE_MISMATCH -> HttpStatus.FORBIDDEN;                      // 403 越权
            case AUDIT_FAILURE -> HttpStatus.SERVICE_UNAVAILABLE;             // 503 fail-closed
        };
    }
}
