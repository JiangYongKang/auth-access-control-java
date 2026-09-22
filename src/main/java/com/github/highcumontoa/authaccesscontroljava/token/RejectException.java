package com.github.highcumontoa.authaccesscontroljava.token;

public class RejectException extends RuntimeException {

    private final RejectReason reason;

    public RejectException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectReason reason() {
        return reason;
    }
}
