package com.github.ryneal.mitre.oidc.config.connect;

import org.mitre.openid.connect.view.UserInfoJWTView;
import org.mitre.openid.connect.view.UserInfoView;
import org.mitre.openid.connect.web.UserInfoEndpoint;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.Filter;

@Configuration
@ConditionalOnProperty(havingValue = "true", name = "openid.connect.endpoints.oidc.userinfo.enabled", matchIfMissing = true)
@Order(190)
public class UserInfoResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final String PATTERN = "/" + org.mitre.openid.connect.web.UserInfoEndpoint.URL + "**";

    private final Filter corsFilter;

    private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public UserInfoResourceServerConfig(@Qualifier("corsFilter") Filter corsFilter,
                                        OAuth2AuthenticationEntryPoint authenticationEntryPoint) {
        this.corsFilter = corsFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Bean
    @ConditionalOnMissingBean(UserInfoEndpoint.class)
    protected UserInfoEndpoint userInfoEndpoint() {
        return new UserInfoEndpoint();
    }

    @Bean(name = UserInfoJWTView.VIEWNAME)
    @ConditionalOnMissingBean(name = UserInfoJWTView.VIEWNAME)
    protected UserInfoJWTView userInfoJwtView() {
        return new UserInfoJWTView();
    }

    @Bean(name = UserInfoView.VIEWNAME)
    @ConditionalOnMissingBean(name = UserInfoView.VIEWNAME)
    protected UserInfoView userInfoView() {
        return new UserInfoView();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .requestMatchers()
                .antMatchers(PATTERN)
                .and()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                .and()
                .addFilterBefore(corsFilter, SecurityContextPersistenceFilter.class)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ;
        // @formatter:on
    }

}