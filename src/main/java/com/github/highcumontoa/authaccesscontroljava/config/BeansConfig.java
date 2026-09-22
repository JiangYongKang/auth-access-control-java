package com.github.highcumontoa.authaccesscontroljava.config;

import java.time.Clock;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.authaccesscontroljava.token.FileTokenStateStore;
import com.github.highcumontoa.authaccesscontroljava.token.TokenStateStore;

/**
 * 通用 Bean 配置。
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class BeansConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public TokenStateStore tokenStateStore(AuthProperties properties, Clock clock, ObjectMapper objectMapper) {
        return new FileTokenStateStore(properties, clock, objectMapper);
    }
}
