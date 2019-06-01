package org.servicedx.oauth.server;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.servicedx.security.resource.OAuth2Constants;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@FrameworkEndpoint
public class RevokeTokenEndpoint implements OAuth2Constants
{

	@Resource(name = "tokenServices")
	ConsumerTokenServices tokenServices;

	@RequestMapping(method = RequestMethod.DELETE, value = OAUTH_TOKEN_REVOKE)
	@ResponseBody
	public void revokeToken(HttpServletRequest request)
	{
		String authorization = request.getHeader(AUTHORIZATION);
		if (authorization != null && authorization.contains(BEARER.trim()))
		{
			String tokenId = authorization.substring(BEARER.trim().length() + 1);
			tokenServices.revokeToken(tokenId);
		}
	}

}