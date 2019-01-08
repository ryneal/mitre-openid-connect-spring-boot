package com.github.ryneal.mitre.oidc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

/**
 * Sets source of User information as the spring security stock JDBC User Details
 * @author barretttucker
 *
 */
@Order(610)
@Configuration
@EnableGlobalAuthentication
public class JdbcDataSourceAuthenticationConfig extends WebSecurityConfigurerAdapter {

    private final DataSource dataSource;

    private final PasswordEncoder userPasswordEncoder;

    public JdbcDataSourceAuthenticationConfig(DataSource dataSource,
                                              @Qualifier("userPasswordEncoder") PasswordEncoder userPasswordEncoder) {
        this.dataSource = dataSource;
        this.userPasswordEncoder = userPasswordEncoder;
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception{
        auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(userPasswordEncoder);
    }

}
