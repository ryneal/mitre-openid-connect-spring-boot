package com.github.ryneal.mitre.oidc;

import com.github.ryneal.mitre.oidc.config.annotation.EnableOpenIDConnectServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Configuration;

/**
 * @author barretttucker
 */
@Configuration
@SpringBootApplication
@EnableOpenIDConnectServer
public class TestBootApplication extends SpringBootServletInitializer {

    public static void main(final String[] args) {
        SpringApplication.run(TestBootApplication.class, args);
    }

}
