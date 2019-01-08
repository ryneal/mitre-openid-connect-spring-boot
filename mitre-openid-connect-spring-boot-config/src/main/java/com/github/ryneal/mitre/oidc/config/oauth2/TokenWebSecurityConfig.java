package com.github.ryneal.mitre.oidc.config.oauth2;

import org.mitre.oauth2.web.IntrospectionEndpoint;
import org.mitre.oauth2.web.RevocationEndpoint;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.Filter;
import java.util.Collections;
import java.util.HashSet;

/**
 * Configuration of OAuth 2.0 endpoints for token management (granting, inspection and revocation)
 * @author barretttucker
 *
 */
@Configuration
@Order(110)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Filter corsFilter;

    private final OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    private final UserDetailsService clientUserDetailsService;

    private final UserDetailsService uriEncodedClientUserDetailsService;

    private final OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler;

    private final ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;

    private final JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter;

    private final PasswordEncoder clientPasswordEncoder;

    public TokenWebSecurityConfig(@Qualifier("corsFilter") Filter corsFilter,
                                  OAuth2AuthenticationEntryPoint authenticationEntryPoint,
                                  @Qualifier("clientUserDetailsService") UserDetailsService clientUserDetailsService,
                                  @Qualifier("uriEncodedClientUserDetailsService") UserDetailsService uriEncodedClientUserDetailsService,
                                  OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler,
                                  @Lazy ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter,
                                  @Lazy JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter,
                                  @Qualifier("clientPasswordEncoder") PasswordEncoder clientPasswordEncoder) {
        this.corsFilter = corsFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.clientUserDetailsService = clientUserDetailsService;
        this.uriEncodedClientUserDetailsService = uriEncodedClientUserDetailsService;
        this.oAuth2AccessDeniedHandler = oAuth2AccessDeniedHandler;
        this.clientCredentialsTokenEndpointFilter = clientCredentialsTokenEndpointFilter;
        this.jwtBearerClientAssertionTokenEndpointFilter = jwtBearerClientAssertionTokenEndpointFilter;
        this.clientPasswordEncoder = clientPasswordEncoder;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(clientUserDetailsService).passwordEncoder(clientPasswordEncoder);
        auth.userDetailsService(uriEncodedClientUserDetailsService).passwordEncoder(clientPasswordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean(IntrospectionEndpoint.class)
    protected IntrospectionEndpoint introspectionEndpoint(){
        return new IntrospectionEndpoint();
    }

    @Bean
    @ConditionalOnMissingBean(RevocationEndpoint.class)
    protected RevocationEndpoint revocationEndpoint(){
        return new RevocationEndpoint();
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(ClientCredentialsTokenEndpointFilter.class)
    public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter(
            @Qualifier("clientAuthenticationMatcher")
            final MultiUrlRequestMatcher clientAuthenticationMatcher) throws Exception{
        final ClientCredentialsTokenEndpointFilter filter = new ClientCredentialsTokenEndpointFilter();
        filter.setRequiresAuthenticationRequestMatcher(clientAuthenticationMatcher);
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    @Autowired
    @Bean
    @ConditionalOnMissingBean(JWTBearerClientAssertionTokenEndpointFilter.class)
    public JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter(
            @Qualifier("clientAuthenticationMatcher")
            final MultiUrlRequestMatcher clientAuthenticationMatcher, final JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider){
        final JWTBearerClientAssertionTokenEndpointFilter filter = new JWTBearerClientAssertionTokenEndpointFilter(
                clientAuthenticationMatcher);
        filter.setAuthenticationManager(new ProviderManager(
                Collections.<AuthenticationProvider> singletonList(jwtBearerAuthenticationProvider)));
        return filter;
    }

    @Bean
    @ConditionalOnMissingBean(JWTBearerAuthenticationProvider.class)
    public JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider(){
        return new JWTBearerAuthenticationProvider();
    }

    @Bean(name = "clientAuthenticationMatcher")
    @ConditionalOnMissingBean(type = {
            "javax.servlet.http.HttpServletRequest.MultiUrlRequestMatcher"}, name = "clientAuthenticationMatcher")
    public MultiUrlRequestMatcher clientAuthenticationMatcher(){
        final HashSet<String> urls = new HashSet<String>();
        urls.add("/introspect");
        urls.add("/revoke");
        urls.add("/token");
        return new MultiUrlRequestMatcher(urls);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception{
        // @formatter:off
		http
			.requestMatchers()
				.antMatchers(
						"/token", 
						"/"+ IntrospectionEndpoint.URL+"**",
						"/"+ RevocationEndpoint.URL+"**")
				.and()
			.httpBasic()
				.authenticationEntryPoint(authenticationEntryPoint)
				.and()
			.authorizeRequests()
				.antMatchers(HttpMethod.OPTIONS, "/token").permitAll()
				.antMatchers("/token").authenticated()
				.and()
			.addFilterAfter(jwtBearerClientAssertionTokenEndpointFilter, AbstractPreAuthenticatedProcessingFilter.class)
			.addFilterAfter(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class)
			.addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
			
			.exceptionHandling()
				.authenticationEntryPoint(authenticationEntryPoint)
				.accessDeniedHandler(oAuth2AccessDeniedHandler)
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		;
		// @formatter:on
    }
}
