package com.github.highcumontoa.authaccesscontroljava.support;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 全进程共享的 JSON 编解码配置。
 */
public final class JsonCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonCodec() {
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
