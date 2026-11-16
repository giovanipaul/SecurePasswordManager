package io.github.giovanipaul.securepasswordmanager.service;

import java.io.IOException;

/**
 * Fetches one HaveIBeenPwned password-range response. The caller sends only the
 * first 5 characters of the password's SHA-1 hash (k-anonymity), so the full
 * hash and the password itself never leave the machine.
 */
public interface BreachRangeFetcher {

	/**
	 * Returns the raw range response for a 5-character hash prefix: one
	 * {@code SUFFIX:COUNT} line per breached hash sharing that prefix.
	 */
	String fetchRange(String prefix) throws IOException, InterruptedException;
}
