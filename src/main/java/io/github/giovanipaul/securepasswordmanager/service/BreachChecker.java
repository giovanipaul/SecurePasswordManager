package io.github.giovanipaul.securepasswordmanager.service;

import io.github.giovanipaul.securepasswordmanager.crypto.CryptoService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Checks a password against the HaveIBeenPwned breach data using k-anonymity:
 * only the first 5 characters of the password's SHA-1 hash are sent, and the
 * matching suffix is looked up locally in the returned range. The password and
 * the full hash never leave the machine.
 *
 * <p>
 * A result of 0 means the password was not found in the breach data. That does
 * not prove the password is strong; it only means it has not appeared in a
 * known public breach.
 */
public final class BreachChecker {

	private static final int PREFIX_LENGTH = 5;

	private final BreachRangeFetcher fetcher;

	public BreachChecker() {
		this(new HaveIBeenPwnedClient());
	}

	/**
	 * Test seam: uses the given range fetcher instead of the live HaveIBeenPwned
	 * client, so checks run without network access.
	 */
	public BreachChecker(BreachRangeFetcher fetcher) {
		if (fetcher == null) {
			throw new IllegalArgumentException("Breach range fetcher cannot be null.");
		}
		this.fetcher = fetcher;
	}

	/**
	 * Returns how many times the password appeared in known data breaches, or 0
	 * when it was not found. The password characters are owned by the caller and
	 * are not wiped here.
	 */
	public long check(char[] password) throws IOException {
		if (password == null || password.length == 0) {
			throw new IllegalArgumentException("Password cannot be empty.");
		}
		String hash = sha1Hex(password);
		String prefix = hash.substring(0, PREFIX_LENGTH);
		String suffix = hash.substring(PREFIX_LENGTH);
		String range;
		try {
			range = fetcher.fetchRange(prefix);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Breach check interrupted.", e);
		}
		if (range == null) {
			throw new IOException("HaveIBeenPwned returned an empty response.");
		}
		return findOccurrences(range, suffix);
	}

	private static long findOccurrences(String range, String suffix) throws IOException {
		for (String line : range.split("\\R")) {
			String trimmed = line.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			String[] parts = trimmed.split(":", -1);
			if (parts.length != 2) {
				continue;
			}
			if (!parts[0].equalsIgnoreCase(suffix)) {
				continue;
			}
			try {
				return Long.parseLong(parts[1].trim());
			} catch (NumberFormatException e) {
				throw new IOException("HaveIBeenPwned returned an unreadable breach count.", e);
			}
		}
		return 0;
	}

	private static String sha1Hex(char[] password) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
			byte[] bytes = new byte[encoded.remaining()];
			encoded.get(bytes);
			byte[] hash = digest.digest(bytes);
			CryptoService.wipe(bytes);
			StringBuilder hex = new StringBuilder(hash.length * 2);
			for (byte b : hash) {
				hex.append(String.format("%02X", b));
			}
			return hex.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-1 is required for breach checking.", e);
		}
	}
}
