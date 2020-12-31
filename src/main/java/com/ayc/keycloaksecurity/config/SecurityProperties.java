package com.ayc.keycloaksecurity.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private String[] whitelist = new String[] {};

    private Cors cors = new Cors();

    @Getter
    @Setter
    class Cors {
        private String[] origins = new String[] {};
        private String[] allowedMethods = new String[] {HttpMethod.GET.name(), HttpMethod.POST.name(),
                HttpMethod.PUT.name(), HttpMethod.PATCH.name(), HttpMethod.DELETE.name(), HttpMethod.HEAD.name(),
                HttpMethod.TRACE.name(), HttpMethod.OPTIONS.name()};
        private Boolean allowCredentials = Boolean.TRUE;
        private String allowedHeader = "*";
    }
}
