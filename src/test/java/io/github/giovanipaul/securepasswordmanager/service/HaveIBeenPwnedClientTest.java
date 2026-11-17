package io.github.giovanipaul.securepasswordmanager.service;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import static org.junit.jupiter.api.Assertions.*;

class HaveIBeenPwnedClientTest {
	@Test
	void readsWithinLimitAndRejectsOversizedResponse() {
		var subscriber = new HaveIBeenPwnedClient.BoundedBodySubscriber();
		var subscription = new TestSubscription();
		subscriber.onSubscribe(subscription);
		subscriber.onNext(List.of(ByteBuffer.wrap("ok".getBytes(StandardCharsets.UTF_8))));
		subscriber.onComplete();
		assertArrayEquals("ok".getBytes(StandardCharsets.UTF_8), subscriber.getBody().toCompletableFuture().join());
		var oversized = new HaveIBeenPwnedClient.BoundedBodySubscriber();
		var oversizedSubscription = new TestSubscription();
		oversized.onSubscribe(oversizedSubscription);
		oversized.onNext(List.of(ByteBuffer.wrap(new byte[1024 * 1024]), ByteBuffer.wrap(new byte[1])));
		assertTrue(oversizedSubscription.cancelled);
		assertThrows(CompletionException.class, () -> oversized.getBody().toCompletableFuture().join());
	}

	private static class TestSubscription implements Flow.Subscription {
		private boolean cancelled;
		@Override
		public void request(long count) {
		}
		@Override
		public void cancel() {
			cancelled = true;
		}
	}

	@Test
	void rejectsInvalidPrefixesWithoutTouchingTheNetwork() {
		HaveIBeenPwnedClient client = new HaveIBeenPwnedClient();
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange(null));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("abc"));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("5BAA61"));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("5baa6"));
	}
}
