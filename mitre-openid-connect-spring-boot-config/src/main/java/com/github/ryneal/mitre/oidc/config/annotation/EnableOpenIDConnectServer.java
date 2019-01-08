package com.github.ryneal.mitre.oidc.config.annotation;

import com.github.ryneal.mitre.oidc.config.OpenIDConnectServerConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Enables OpenID Connect Server configuration facility.
 * To be used together with {@link org.springframework.context.annotation.Configuration Configuration}
 * or {@link org.springframework.boot.autoconfigure.SpringBootApplication SpringBootApplication} classes.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(OpenIDConnectServerConfig.class)
public @interface EnableOpenIDConnectServer {


}

