package com.luminn.resource.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.luminn.resource.service.JwtValidatorService;
import com.luminn.resource.service.UserInfoService;

@Component
public class AuthRequestFilter extends OncePerRequestFilter {
	
	@Autowired
	private UserInfoService userInfo;
	
	@Autowired
	private JwtValidatorService validator;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");
		String token = null;
		if (authHeader != null) {
			if (authHeader.startsWith("Bearer ")) {
				token = authHeader.substring(7);
				if (SecurityContextHolder.getContext().getAuthentication() == null) {
					if (validator.isValid(token)) {
						UserDetails user = userInfo.loadUserByUsername(userInfo.getName());
						UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
						userToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(userToken);
					}
				}
			}
		}
		filterChain.doFilter(request, response);
	}
}
