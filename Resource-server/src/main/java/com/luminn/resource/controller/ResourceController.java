package com.luminn.resource.controller;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
	
	@GetMapping("/")
	public String index() {
		JSONObject result = new JSONObject();
		result.put("message", "Welcome to secure resource!");
		return result.toString();
	}

	@GetMapping("/Test")
	public String Test() {
		JSONObject result = new JSONObject();
		result.put("message 1", "Test");
		return result.toString();
	}

	@PostMapping("/")
	public String postIndex() {
		JSONObject result = new JSONObject();
		result.put("post method", "that is working :D!");
		return result.toString();
	}
}
