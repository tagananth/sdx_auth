package org.servicedx.oauth.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.servicedx.bean.model.Roles;
import org.servicedx.bean.model.Users;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class OAuth2UserDetails implements UserDetails
{
	private static final long	serialVersionUID	= 7116369654223628650L;
	private Users				user;

	public OAuth2UserDetails(Users user)
	{
		this.user = user;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities()
	{
		List<GrantedAuthority> authorities = new ArrayList<>();
		for (Roles role : user.getRoles())
		{
			authorities.add(new SimpleGrantedAuthority(role.getRoleId().toUpperCase()));
		}
		return authorities;
	}

	@Override
	public String getPassword()
	{
		return user.getPassword();
	}

	@Override
	public String getUsername()
	{
		return user.getUserId() + "";
	}

	@Override
	public boolean isAccountNonExpired()
	{
		return true;
	}

	@Override
	public boolean isAccountNonLocked()
	{
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired()
	{
		return true;
	}

	@Override
	public boolean isEnabled()
	{
		return true;
	}

	public Users getUser()
	{
		return user;
	}

	public void setUser(Users user)
	{
		this.user = user;
	}

}
