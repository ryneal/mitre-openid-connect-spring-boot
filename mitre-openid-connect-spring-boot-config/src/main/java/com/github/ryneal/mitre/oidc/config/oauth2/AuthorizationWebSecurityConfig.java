package com.github.ryneal.mitre.oidc.config.oauth2;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.Filter;

@Order(710)
@Configuration
public class AuthorizationWebSecurityConfig extends WebSecurityConfigurerAdapter {

	private final Filter authRequestFilter;

	public AuthorizationWebSecurityConfig(@Qualifier("authRequestFilter") Filter authRequestFilter) {
		this.authRequestFilter = authRequestFilter;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests()
				.antMatchers("/authorize")
				.hasRole("USER")
				.and()
			.addFilterAfter(authRequestFilter, SecurityContextPersistenceFilter.class)
		;
		// @formatter:on
	}
	
}
