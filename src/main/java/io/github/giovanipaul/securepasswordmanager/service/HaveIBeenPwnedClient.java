package io.github.giovanipaul.securepasswordmanager.service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Live HaveIBeenPwned range client. Sends only the 5-character hash prefix;
 * the password and the full hash never leave the machine.
 */
final class HaveIBeenPwnedClient implements BreachRangeFetcher {

	private static final String RANGE_URL = "https://api.pwnedpasswords.com/range/";
	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
	private static final int MAX_RESPONSE_BYTES = 1024 * 1024;

	private final HttpClient httpClient;

	HaveIBeenPwnedClient() {
		this(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build());
	}

	HaveIBeenPwnedClient(HttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String fetchRange(String prefix) throws IOException, InterruptedException {
		if (prefix == null || !prefix.matches("[0-9A-F]{5}")) {
			throw new IllegalArgumentException("Hash prefix must be 5 uppercase hex characters.");
		}
		HttpRequest request = HttpRequest.newBuilder(URI.create(RANGE_URL + prefix))
				.header("User-Agent", "SecurePasswordManager/1.1.0")
				.header("Add-Padding", "true")
				.timeout(REQUEST_TIMEOUT)
				.GET()
				.build();
		HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
		if (response.statusCode() != 200) {
			throw new IOException("HaveIBeenPwned returned HTTP " + response.statusCode() + ".");
		}
		byte[] body = response.body();
		if (body == null || body.length > MAX_RESPONSE_BYTES) {
			throw new IOException("HaveIBeenPwned returned an unexpected response.");
		}
		return new String(body, StandardCharsets.UTF_8);
	}
}
