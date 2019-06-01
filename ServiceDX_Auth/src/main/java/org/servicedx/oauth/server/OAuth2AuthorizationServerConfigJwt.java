package org.servicedx.oauth.server;

import java.util.Arrays;

import org.servicedx.security.resource.IPath.ERole;
import org.servicedx.security.resource.OAuth2Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfigJwt extends AuthorizationServerConfigurerAdapter implements OAuth2Constants
{

	@Autowired
	private ClientDetailsService		clientDetailsService;

	@Autowired
	private UserApprovalHandler			userApprovalHandler;

	@Autowired
	@Qualifier("userDetailsService")
	private OAuth2UserDetailsService	userDetailsService;

	@Autowired
	@Qualifier(AUTHENTICATION_MANAGER_BEAN)
	private AuthenticationManager		authenticationManager;

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception
	{
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
		oauthServer.realm(REALM);
	}

	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception
	{
		clients.inMemory()//
				.withClient(SOM_APPLICATION)//
				.secret(new BCryptPasswordEncoder().encode(SOM_SECRET))//
				.authorizedGrantTypes(PASSWORD, REFRESH_TOKEN)//
				.authorities(ERole.Administrator.name().toUpperCase(), ERole.Supervisor.name().toUpperCase(), ERole.User.name().toUpperCase())//
				.scopes(READ, WRITE, TRUST)//
				.accessTokenValiditySeconds(THIRTY_DAYS)// For Testing And Development Set for 30
														// Days
				.refreshTokenValiditySeconds(THIRTY_DAYS);
	}

	@Override
	public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception
	{
		TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(customTokenEnhancer(), accessTokenConverter()));

		endpoints.tokenStore(tokenStore())//
				.tokenEnhancer(enhancerChain)//
				.authenticationManager(authenticationManager)//
				.userDetailsService(userDetailsService)//
				.userApprovalHandler(userApprovalHandler);
	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices()
	{
		final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}

	@Bean
	public TokenStore tokenStore()
	{
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	protected JwtAccessTokenConverter accessTokenConverter()
	{
		// KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new
		// ClassPathResource("jwt.jks"), "mySecretKey".toCharArray());
		// JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		// converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));

		// -- for the simple demo purpose, used the secret for signing.
		// -- for production, it is recommended to use public/private key pair
		// JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		// converter.setSigningKey(SOM_APPLICATION);

		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey(SOM_APPLICATION);
		return converter;

	}

	@Bean
	@Autowired
	public TokenStoreUserApprovalHandler userApprovalHandler(TokenStore tokenStore)
	{
		TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();
		handler.setTokenStore(tokenStore);
		handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
		handler.setClientDetailsService(clientDetailsService);
		return handler;
	}

	@Bean
	@Autowired
	public ApprovalStore approvalStore(TokenStore tokenStore) throws Exception
	{
		TokenApprovalStore store = new TokenApprovalStore();
		store.setTokenStore(tokenStore);
		return store;
	}

	@Bean
	public TokenEnhancer customTokenEnhancer()
	{
		return new CustomTokenEnhancer();
	}

}
