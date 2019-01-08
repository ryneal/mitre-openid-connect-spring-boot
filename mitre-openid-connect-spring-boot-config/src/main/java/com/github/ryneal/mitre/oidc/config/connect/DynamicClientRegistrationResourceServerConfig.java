package com.github.ryneal.mitre.oidc.config.connect;

import org.mitre.openid.connect.view.ClientInformationResponseView;
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint;
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
@ConditionalOnProperty(havingValue = "true", name = "openid.connect.endpoints.oidc.dynamicclientregistration.enabled", matchIfMissing = true)
@Order(200)
public class DynamicClientRegistrationResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final String PATTERN = "/" + org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint.URL + "/**";

    private final Filter corsFilter;

    private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    public DynamicClientRegistrationResourceServerConfig(@Qualifier("corsFilter") Filter corsFilter,
                                                         OAuth2AuthenticationEntryPoint authenticationEntryPoint) {
        this.corsFilter = corsFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Bean
    @ConditionalOnMissingBean(DynamicClientRegistrationEndpoint.class)
    protected DynamicClientRegistrationEndpoint DynamicClientRegistrationEndpoint() {
        return new DynamicClientRegistrationEndpoint();
    }

    @Bean(name = ClientInformationResponseView.VIEWNAME)
    @ConditionalOnMissingBean(name = ClientInformationResponseView.VIEWNAME)
    protected ClientInformationResponseView clientInformationResponseView() {
        return new ClientInformationResponseView();
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
                .and()
                .authorizeRequests()
                .antMatchers(PATTERN)
                .permitAll()
        ;
        // @formatter:on
    }
}
