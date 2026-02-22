package com.snhu.sslserver;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.owasp.html.Sanitizers;
import org.owasp.html.PolicyFactory;

@RestController
public class HandshakeController {
	// Checksum Hash Function
	public String getChecksum(String data) {
		try {
			String algo = "SHA-256";
			MessageDigest md = MessageDigest.getInstance(algo);
			byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(hash);
		}
		catch (NoSuchAlgorithmException e){
			return "Unable to process data";
		}
	}

	// Establish sanitation policy using OWASP sanitizer
	private static final PolicyFactory POLICY = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
	
	private String dataSanitizer(String data) {
		try {
			return POLICY.sanitize(data);
		}
		// If sanitation fails, reject the connection
		catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Request");
		}
	}
	
	// Generate Checksum hash for security testing
	@GetMapping("/handshake")
	public String getHandshake(@RequestParam(value = "data", defaultValue = "kaleb.gallegos@snhu.edu") String data) {
		// Set generic data for test case
		String dataTemplate = "Data: %s";
		String hashTemplate = "Checksum: %s";
		
		// Validate request parameter
		// Check for null or empty values
		if (data == null || data.isEmpty() || data.isBlank()) {
			return "Error: No data received";
		}
		
		// Check for data length and content
		if (data.length() > 1000) {
			return "Error: Data parameter exceeds maximum length";
		}
		// Check for potentially malicious content
		if (data.contains("<script>") || data.contains("</script>")) {
			return "Error: Invalid data parameter";
		}
		
		//Sanitize Request Parameter
		String cleanData = dataSanitizer(data);
		
		// Return formatted output if checks pass
		return "<p>" + String.format(dataTemplate, cleanData) + "</p><p>" + String.format(hashTemplate, getChecksum(cleanData)) + "</p>";
	}
}
