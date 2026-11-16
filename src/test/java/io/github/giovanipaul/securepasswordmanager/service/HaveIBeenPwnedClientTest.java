package io.github.giovanipaul.securepasswordmanager.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HaveIBeenPwnedClientTest {

	@Test
	void rejectsInvalidPrefixesWithoutTouchingTheNetwork() {
		HaveIBeenPwnedClient client = new HaveIBeenPwnedClient();
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange(null));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("abc"));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("5BAA61"));
		assertThrows(IllegalArgumentException.class, () -> client.fetchRange("5baa6"));
	}
}
