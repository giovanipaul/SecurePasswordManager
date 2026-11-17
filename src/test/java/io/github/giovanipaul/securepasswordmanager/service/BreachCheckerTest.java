package io.github.giovanipaul.securepasswordmanager.service;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class BreachCheckerTest {

	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	private static final String PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
	private static final String PASSWORD_PREFIX = "5BAA6";

	@Test
	void returnsBreachCountWhenSuffixMatchesAndSendsOnlyPrefix() throws Exception {
		AtomicReference<String> sentPrefix = new AtomicReference<>();
		BreachChecker checker = new BreachChecker(prefix -> {
			sentPrefix.set(prefix);
			return "0018A45C4D1DEF81644B54AB7F969B88D65:3\n" + PASSWORD_SUFFIX + ":9543778\n";
		});

		assertEquals(9543778, checker.check("password".toCharArray()));
		assertEquals(PASSWORD_PREFIX, sentPrefix.get());
		assertEquals(PASSWORD_PREFIX.length(), 5);
	}

	@Test
	void returnsZeroWhenSuffixAbsent() throws Exception {
		BreachChecker checker = new BreachChecker(
				prefix -> "0018A45C4D1DEF81644B54AB7F969B88D65:3\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n");

		assertEquals(0, checker.check("password".toCharArray()));
	}

	@Test
	void matchesSuffixCaseInsensitively() throws Exception {
		BreachChecker checker = new BreachChecker(prefix -> PASSWORD_SUFFIX.toLowerCase() + ":7\n");

		assertEquals(7, checker.check("password".toCharArray()));
	}

	@Test
	void rejectsMalformedLinesWithoutMatchingSuffix() {
		String range = "garbage\n:5\nABCDEF\n\n0018A45C4D1DEF81644B54AB7F969B88D65:3\n";
		BreachChecker checker = new BreachChecker(prefix -> range);

		assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
	}

	@Test
	void rejectsEmptyAndWhitespaceOnlyResponses() {
		for (String response : new String[]{"", "  \n"}) {
			BreachChecker checker = new BreachChecker(prefix -> response);
			assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
		}
	}

	@Test
	void validatesWholeResponseEvenAfterMatchingLine() {
		BreachChecker checker = new BreachChecker(prefix -> PASSWORD_SUFFIX + ":42\ninvalid\n");
		assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
	}

	@Test
	void acceptsZeroCountPaddingButRejectsNegativeCounts() throws Exception {
		assertEquals(0, new BreachChecker(prefix -> PASSWORD_SUFFIX + ":0\n").check("password".toCharArray()));
		assertThrows(IOException.class,
				() -> new BreachChecker(prefix -> PASSWORD_SUFFIX + ":-1\n").check("password".toCharArray()));
	}

	@Test
	void rejectsUnreadableCountForMatchingSuffix() {
		BreachChecker checker = new BreachChecker(prefix -> PASSWORD_SUFFIX + ":not-a-count\n");

		assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
	}

	@Test
	void rejectsEmptyRangeResponse() {
		BreachChecker checker = new BreachChecker(prefix -> null);

		assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
	}

	@Test
	void propagatesTransportFailures() {
		BreachChecker checker = new BreachChecker(prefix -> {
			throw new IOException("Network unavailable.");
		});

		assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
	}

	@Test
	void reportsInterruptionAsIoFailureAndRestoresInterruptFlag() {
		BreachChecker checker = new BreachChecker(prefix -> {
			throw new InterruptedException();
		});

		try {
			assertThrows(IOException.class, () -> checker.check("password".toCharArray()));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally {
			Thread.interrupted();
		}
	}

	@Test
	void rejectsEmptyAndNullPasswords() {
		BreachChecker checker = new BreachChecker(prefix -> "");
		assertThrows(IllegalArgumentException.class, () -> checker.check(new char[0]));
		assertThrows(IllegalArgumentException.class, () -> checker.check(null));
	}

	@Test
	void rejectsNullFetcher() {
		assertThrows(IllegalArgumentException.class, () -> new BreachChecker(null));
	}
}
