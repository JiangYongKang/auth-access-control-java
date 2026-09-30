package com.github.highcumontoa.authaccesscontroljava.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * 令牌自检响应。无效令牌只返回 {@code active=false} 与可区分的 {@code reason}，
 * 不回显令牌原文，也不包含任何密钥材料。
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntrospectionResponse(boolean active, String reason, String subject,
                                    String clientId, String sessionId, Long exp,
                                    List<String> scope) {
}
