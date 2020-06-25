package com.luminn.resource.service;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserInfoService implements UserDetailsService {
	
	@Value("${user.clientId}")
	private String userName;
	
	@Value("${user.clientSecret}")
	private String userPassword;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return new User(userName, userPassword, new ArrayList<>());
	}
	
	public String getName() {
		return this.userName;
	}
}
