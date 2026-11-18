package io.github.giovanipaul.securepasswordmanager.service;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * Live HaveIBeenPwned range client. Sends only the 5-character hash prefix; the
 * password and the full hash never leave the machine.
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
				.header("User-Agent", "SecurePasswordManager/1.1.0").header("Add-Padding", "true")
				.timeout(REQUEST_TIMEOUT).GET().build();
		HttpResponse<byte[]> response = httpClient.send(request, info -> new BoundedBodySubscriber());
		if (response.statusCode() != 200) {
			throw new IOException("HaveIBeenPwned returned HTTP " + response.statusCode() + ".");
		}
		return new String(response.body(), StandardCharsets.UTF_8);
	}

	static final class BoundedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
		private final CompletableFuture<byte[]> body = new CompletableFuture<>();
		private final ByteArrayOutputStream output = new ByteArrayOutputStream();
		private Flow.Subscription subscription;

		@Override
		public CompletionStage<byte[]> getBody() {
			return body.minimalCompletionStage();
		}

		@Override
		public void onSubscribe(Flow.Subscription subscription) {
			this.subscription = subscription;
			subscription.request(1);
		}

		@Override
		public void onNext(List<ByteBuffer> buffers) {
			for (ByteBuffer buffer : buffers) {
				if (buffer.remaining() > MAX_RESPONSE_BYTES - output.size()) {
					subscription.cancel();
					body.completeExceptionally(new IOException("HaveIBeenPwned returned an oversized response."));
					return;
				}
				byte[] chunk = new byte[buffer.remaining()];
				buffer.get(chunk);
				output.writeBytes(chunk);
			}
			subscription.request(1);
		}

		@Override
		public void onError(Throwable error) {
			body.completeExceptionally(error);
		}

		@Override
		public void onComplete() {
			body.complete(output.toByteArray());
		}
	}
}
