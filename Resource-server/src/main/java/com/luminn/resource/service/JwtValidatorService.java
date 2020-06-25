package com.luminn.resource.service;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

// your new service need this class also UserInfoService class nad AuthRequestFilter class
// of course SecurityConfig class that's it :D
@Service
public class JwtValidatorService {
	private static final String JWT_HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	private static final String GOOGLE = "https://www.googleapis.com/oauth2/v3/userinfo";
	
	@Value("${jwt.security}")
	private String SECRETKEY;
	
	private JSONObject payload;
	
	public boolean isValid(String token) throws IllegalArgumentException {
		String[] parts = token.split("\\.");
		if (parts.length != 3) throw new IllegalArgumentException("Invalid token format");
		final String encodedHeader = header();
		if (!encodedHeader.equals(parts[0])) throw new IllegalArgumentException("JWT header is incorrect: "+parts[0]);
		payload = new JSONObject(decode(parts[1]));
		if (payload.isEmpty()) throw new JSONException("Payload is empty");
		if (!payload.has("exp")) throw new JSONException("Payload doesn't contain expiry");
		final String signature = parts[2];
		String generatedSign = hmacSha256(encodedHeader+"."+encode(payload.toString()));
		return !(new Date(payload.getLong("exp")).before(new Date(System.currentTimeMillis()))) && signature.equals(generatedSign) && checkUserToken(payload.getString("accessToken"));
	}
	private boolean checkUserToken(String accessToken) {
		RestTemplate rest = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
	    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
	    headers.set("Authorization", "Bearer "+accessToken);
	    HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);
	    ResponseEntity<String> result = rest.exchange(GOOGLE, HttpMethod.GET, entity, String.class);
		return result.getStatusCode().equals(HttpStatus.OK);
	}
	private String header() {
		return encode(JWT_HEADER);
	}
	
	private String encode(String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
	
	private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }
	
	private String hmacSha256(String data) {
        try {
            byte[] hash = SECRETKEY.getBytes(StandardCharsets.UTF_8);

            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            return null;
        }
    }
}
