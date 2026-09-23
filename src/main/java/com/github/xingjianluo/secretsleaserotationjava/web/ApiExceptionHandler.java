package com.github.xingjianluo.secretsleaserotationjava.web;

import com.github.xingjianluo.secretsleaserotationjava.error.Reason;
import com.github.xingjianluo.secretsleaserotationjava.error.ServiceException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 将可区分的业务原因映射为 HTTP 状态码与错误体 {@code {error, message}}，
 * 调用方可依据 error 字段机器化地区分各类拒绝原因。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Map<Reason, HttpStatus> STATUS = Map.ofEntries(
            Map.entry(Reason.UNKNOWN_SUBJECT, HttpStatus.FORBIDDEN),
            Map.entry(Reason.UNKNOWN_LEASE, HttpStatus.NOT_FOUND),
            Map.entry(Reason.SCOPE_MISMATCH, HttpStatus.FORBIDDEN),
            Map.entry(Reason.LEASE_EXPIRED, HttpStatus.FORBIDDEN),
            Map.entry(Reason.LEASE_REVOKED, HttpStatus.FORBIDDEN),
            Map.entry(Reason.KEY_VERSION_GRACE_EXPIRED, HttpStatus.CONFLICT),
            Map.entry(Reason.KEY_VERSION_UNKNOWN, HttpStatus.NOT_FOUND),
            Map.entry(Reason.BAD_CIPHERTEXT, HttpStatus.BAD_REQUEST),
            Map.entry(Reason.ROTATION_CONFLICT, HttpStatus.CONFLICT),
            Map.entry(Reason.AUDIT_FAILURE, HttpStatus.SERVICE_UNAVAILABLE));

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<ApiDtos.ErrorResponse> handle(ServiceException ex) {
        HttpStatus status = STATUS.getOrDefault(ex.reason(), HttpStatus.INTERNAL_SERVER_ERROR);
        return ResponseEntity.status(status)
                .body(new ApiDtos.ErrorResponse(ex.reason().name(), ex.getMessage()));
    }
}
