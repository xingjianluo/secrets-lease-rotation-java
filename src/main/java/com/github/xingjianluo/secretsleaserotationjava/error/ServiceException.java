package com.github.xingjianluo.secretsleaserotationjava.error;

/**
 * 业务拒绝统一异常，携带可区分的 {@link Reason}。
 */
public class ServiceException extends RuntimeException {

    private final Reason reason;

    public ServiceException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ServiceException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
