package com.github.highcumontoa.authaccesscontroljava.web;

import com.github.highcumontoa.authaccesscontroljava.token.RejectException;
import com.github.highcumontoa.authaccesscontroljava.token.RejectReason;
import com.github.highcumontoa.authaccesscontroljava.web.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(RejectException.class)
    public ResponseEntity<ErrorResponse> handleReject(RejectException ex) {
        RejectReason reason = ex.reason();
        log.info("Request rejected: reason={}, status={}, detail={}",
                reason.errorCode(), reason.httpStatus().value(), ex.getMessage());
        return ResponseEntity.status(reason.httpStatus())
                .body(new ErrorResponse(reason.errorCode(), ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(RejectReason.INVALID_REQUEST.httpStatus())
                .body(new ErrorResponse(RejectReason.INVALID_REQUEST.errorCode(),
                        "request body is missing or not valid JSON"));
    }
}
