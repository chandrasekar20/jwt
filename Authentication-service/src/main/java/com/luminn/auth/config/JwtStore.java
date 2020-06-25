package com.luminn.auth.config;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

@Service
public class JwtStore {
	//this class actually generate JWT token using secret key and google user access token
	public static final long ACCESS_TOKEN_VALIDITY_SECONDS = 60 * 1000 * 60 * 24;
	private static final String JWT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	
	@Value("${jwt.security}")
	private String SECRETKEY;
	
	//actually google didn't give you refresh token it means null so it is just disappear
	//your google information's put into payload
	public String createToken(String subject, OAuth2AccessToken oAuth2AccessToken, OAuth2RefreshToken oAuth2RefreshToken) {
		String token = "";
		JSONObject payload = new JSONObject();
		payload.put("sub", subject);
		payload.put("accessToken", oAuth2AccessToken.getTokenValue());
		payload.put("type", oAuth2AccessToken.getTokenType().getValue());
		payload.put("refreshToken", oAuth2RefreshToken);
		payload.put("exp", System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_SECONDS);
		String signature = hmacSha256(encode(JWT_HEADER.getBytes()) + "." + encode(payload.toString().getBytes()));
		token = encode(JWT_HEADER.getBytes()) + "." + encode(payload.toString().getBytes())+ "." + signature;
		return token;
	}
	
	private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
	private String hmacSha256(String data) {
	    try {
	        byte[] hash = SECRETKEY.getBytes(StandardCharsets.UTF_8);

	        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
	        SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
	        sha256Hmac.init(secretKey);

	        byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));

	        return encode(signedBytes);
	    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
	        return null;
	    }
	}
}
