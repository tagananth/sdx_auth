package org.servicedx.oauth.server;

import org.servicedx.security.resource.OAuth2Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter implements OAuth2Constants
{
	@Autowired
	@Qualifier("userDetailsService")
	private OAuth2UserDetailsService userDetailsService;

	@Override
	@Order(Ordered.HIGHEST_PRECEDENCE)
	protected void configure(final HttpSecurity http) throws Exception
	{
		// @formatter:off
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()//
				.csrf().disable()//
				.authorizeRequests()//
				.antMatchers("/oauth/token").permitAll()//
				.anyRequest().authenticated().and()//
				.httpBasic().realmName(REALM);
		// @formatter:on
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception
	{
		return super.authenticationManagerBean();
	}

}
