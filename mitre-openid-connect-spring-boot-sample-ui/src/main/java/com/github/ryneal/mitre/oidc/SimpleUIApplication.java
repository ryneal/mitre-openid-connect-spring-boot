package com.github.ryneal.mitre.oidc;

import com.github.ryneal.mitre.oidc.config.annotation.EnableOpenIDConnectServer;
import org.mitre.oauth2.web.CorsFilter;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@EnableOpenIDConnectServer
public class SimpleUIApplication {

    public static void main(String[] args) {
        SpringApplication.run(SimpleUIApplication.class, args);
    }

    @Configuration
    public static class LoginConfiguration extends WebSecurityConfigurerAdapter {

        private final CorsFilter corsFilter;

        private final AuthenticationTimeStamper authenticationTimeStamper;

        public LoginConfiguration(CorsFilter corsFilter,
                                  AuthenticationTimeStamper authenticationTimeStamper) {
            this.corsFilter = corsFilter;
            this.authenticationTimeStamper = authenticationTimeStamper;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .sessionManagement()
                    .enableSessionUrlRewriting(false)
                    .and()
                    .csrf()
                    .and()
                    .formLogin()
                    .loginPage("/")
                    .loginProcessingUrl("/login")
                    .successHandler(authenticationTimeStamper)
                    .failureUrl("/?error")
                    .permitAll()
                    .and()
                    .authorizeRequests()
                    .antMatchers("/**")
                    .permitAll()
                    .and()
                    .addFilterBefore(corsFilter, SecurityContextPersistenceFilter.class)
                    .logout()
                    .logoutSuccessUrl("/?logout")
                    .permitAll()
                    .and()
                    .exceptionHandling().accessDeniedPage("/?denied") //in this simple case usually due to a InvalidCsrfTokenException after session timeout
                    .and()
                    .anonymous()
                    .and()
                    .headers()
                    .frameOptions().deny()
            ;
            // @formatter:on
        }

    }

    @Configuration
    public static class WebMvcConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/").setViewName("index");
            registry.addViewController("/sampleclient").setViewName("sampleclient");
        }

    }

}
