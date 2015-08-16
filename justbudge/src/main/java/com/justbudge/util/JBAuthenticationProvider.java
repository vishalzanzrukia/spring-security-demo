package com.justbudge.util;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import com.justbudge.bean.LoginToken;
import com.justbudge.dao.base.BaseDaoImpl;

/**
 * The <code>JBAuthenticationProvider</code> class provides the custom authentication using encryption of password
 * 
 * @author vzanzrukia
 * @version 1.0
 * 
 */
@Repository
public class JBAuthenticationProvider extends BaseDaoImpl implements UserDetailsService
{
	/**
	 * defining logger.
	 */
	private static Logger	log	= Logger.getLogger(JBAuthenticationProvider.class);

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
	{
		log.debug("running loadUserByUsername method");
		LoginToken loginToken = getDaoFactory().getLoginDao().getLoginToken(username);

		Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();

		SimpleGrantedAuthority adminAuthority = new SimpleGrantedAuthority(JBConstants.ADMIN_ROLE);
		SimpleGrantedAuthority backOfficeAuthority = new SimpleGrantedAuthority(JBConstants.BACK_OFFICE_ROLE);
		SimpleGrantedAuthority businessUserAuthority = new SimpleGrantedAuthority(JBConstants.BUSINESS_ROLE);

		if (loginToken.getRoleDesc().equals(JBConstants.ADMIN_ROLE))
		{
			authorities.add(adminAuthority);
		}
		else if (loginToken.getRoleDesc().equals(JBConstants.BACK_OFFICE_ROLE))
		{
			authorities.add(backOfficeAuthority);
		}
		else if (loginToken.getRoleDesc().equals(JBConstants.BUSINESS_ROLE))
		{
			authorities.add(businessUserAuthority);
		}
		else
		{
			log.warn("execution must not come over here. do we need to define new role for system????");
		}

		log.debug("creating user with username : " + username + " and authorities : " + authorities);
		UserDetails user = new User(username, loginToken.getPassword(), true, true, true, true, authorities);
		return user;
	}

}
