package com.ayc.keycloaksecurity.config;

import com.ayc.keycloaksecurity.util.SecurityUtil;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({ KeycloakSecurityConfig.class, SecurityUtil.class})
public @interface EnableKeycloakSecurity {
}
