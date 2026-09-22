package com.github.highcumontoa.authaccesscontroljava.web.dto;

public class ErrorResponse {
    private String error;
    private String error_description;

    public ErrorResponse() {
    }

    public ErrorResponse(String error, String errorDescription) {
        this.error = error;
        this.error_description = errorDescription;
    }

    public String getError() { return error; }
    public String getError_description() { return error_description; }
}
