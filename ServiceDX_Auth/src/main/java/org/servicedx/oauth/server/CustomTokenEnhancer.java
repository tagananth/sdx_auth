package org.servicedx.oauth.server;

import java.util.HashMap;
import java.util.Map;

import org.servicedx.security.resource.IPath;
import org.servicedx.util.CommonValidator;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class CustomTokenEnhancer implements TokenEnhancer, IPath
{

	private static final long serialVersionUID = 2333742099695592008L;

	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication)
	{
		OAuth2UserDetails user = (OAuth2UserDetails) authentication.getPrincipal();
		final Map<String, Object> additionalInfo = new HashMap<>();

		additionalInfo.put(USER_ID, user.getUser().getUserId());
		additionalInfo.put(CUSTOMER_ID, user.getUser().getCustomerId());
		additionalInfo.put(CUSTOMER_NAME, user.getUser().getCustomerName());

		String fullName = user.getUser().getFirstName();
		if (CommonValidator.isNotNullNotEmpty(user.getUser().getLastName(), fullName))
		{
			fullName = user.getUser().getLastName() + COMMA_SPACE + fullName;
		}
		additionalInfo.put(USER_FULL_NAME, fullName);

		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

		return accessToken;
	}

}
