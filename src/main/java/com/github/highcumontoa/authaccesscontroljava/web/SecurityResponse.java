package com.github.highcumontoa.authaccesscontroljava.web;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletResponse;

/**
 * 过滤器层直接写出的 JSON 错误响应（过滤器异常不经过 ControllerAdvice）。
 */
public final class SecurityResponse {

    private SecurityResponse() {
    }

    public static void write(ObjectMapper objectMapper, HttpServletResponse response, int status, String error,
                      String reason) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("reason", reason);
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
