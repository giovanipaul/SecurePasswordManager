package io.github.giovanipaul.securepasswordmanager.ui;

import io.github.giovanipaul.securepasswordmanager.crypto.CryptoService;
import io.github.giovanipaul.securepasswordmanager.service.BreachChecker;
import io.github.giovanipaul.securepasswordmanager.service.VaultService;
import io.github.giovanipaul.securepasswordmanager.storage.VaultRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import javax.crypto.AEADBadTagException;

import static org.junit.jupiter.api.Assertions.*;

class ConsoleUITest {
	@TempDir
	Path tempDir;

	@Test
	void firstRunCreatesVaultAndDisplaysWelcomeMenu() throws Exception {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "0")
				+ System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		VaultRepository repository = new VaultRepository(new CryptoService());

		ConsoleUI ui = new ConsoleUI(repository, new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5));
		ui.run(vaultPath);

		String terminal = output.toString(StandardCharsets.UTF_8);
		assertTrue(terminal.contains("SECURE PASSWORD MANAGER"));
		assertTrue(terminal.contains("MAIN MENU"));
		assertTrue(terminal.contains("New encrypted vault created and unlocked"));
		assertTrue(java.nio.file.Files.exists(vaultPath));
		assertTrue(repository.load(vaultPath, "StrongMaster1!".toCharArray()).getEntries().isEmpty());
	}

	@Test
	void numberedMenuAddsAndPersistsCredential() throws Exception {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "2", "Example",
				"giovani", "1", "CredentialPass1!", "portfolio", "0") + System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		VaultRepository repository = new VaultRepository(new CryptoService());

		ConsoleUI ui = new ConsoleUI(repository, new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5));
		ui.run(vaultPath);

		var loaded = repository.load(vaultPath, "StrongMaster1!".toCharArray());
		assertEquals(1, loaded.getEntries().size());
		assertEquals("Example", loaded.getEntries().get(0).getSite());
		assertTrue(output.toString(StandardCharsets.UTF_8).contains("Vault saved securely"));
	}

	@Test
	void invalidCommandShowsExamplesInsteadOfCrashing() {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "not-a-command", "0")
				+ System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();

		ConsoleUI ui = new ConsoleUI(new VaultRepository(new CryptoService()), new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5));
		ui.run(vaultPath);

		String terminal = output.toString(StandardCharsets.UTF_8);
		assertTrue(terminal.contains("Unknown option"));
		assertTrue(terminal.contains("'list', 'add', 'help', or 'exit'"));
	}

	@Test
	void changesMasterPasswordAndInvalidatesOldPassword() throws Exception {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "13", "StrongMaster1!",
				"Replacement2@", "Replacement2@", "0") + System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		VaultRepository repository = new VaultRepository(new CryptoService());

		ConsoleUI ui = new ConsoleUI(repository, new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5));
		ui.run(vaultPath);

		assertTrue(output.toString(StandardCharsets.UTF_8).contains("Master password changed"));
		assertThrows(AEADBadTagException.class, () -> repository.load(vaultPath, "StrongMaster1!".toCharArray()));
		assertNotNull(repository.load(vaultPath, "Replacement2@".toCharArray()));
	}

	@Test
	void breachCheckReportsCompromisedPassword() {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "14", "password", "0")
				+ System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		BreachChecker checker = new BreachChecker(prefix -> "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9543778\n");

		ConsoleUI ui = new ConsoleUI(new VaultRepository(new CryptoService()), new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5), checker);
		ui.run(vaultPath);

		String terminal = output.toString(StandardCharsets.UTF_8);
		assertTrue(terminal.contains("was seen 9543778 times in breach data"));
		assertTrue(terminal.contains("Only the first 5 characters of the password hash are sent"));
	}

	@Test
	void breachCheckReportsSafePassword() {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "14", "password", "0")
				+ System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		BreachChecker checker = new BreachChecker(prefix -> "0018A45C4D1DEF81644B54AB7F969B88D65:3\n");

		ConsoleUI ui = new ConsoleUI(new VaultRepository(new CryptoService()), new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5), checker);
		ui.run(vaultPath);

		assertTrue(output.toString(StandardCharsets.UTF_8)
				.contains("This password was not found in the HaveIBeenPwned breach data."));
	}

	@Test
	void breachCheckReportsNetworkFailureWithoutCrashing() {
		Path vaultPath = tempDir.resolve("vault.json");
		String input = String.join(System.lineSeparator(), "StrongMaster1!", "StrongMaster1!", "14", "password", "0")
				+ System.lineSeparator();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		BreachChecker checker = new BreachChecker(prefix -> {
			throw new IOException("Network unavailable.");
		});

		ConsoleUI ui = new ConsoleUI(new VaultRepository(new CryptoService()), new VaultService(),
				new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), new PrintStream(output),
				Duration.ofMinutes(5), checker);
		ui.run(vaultPath);

		assertTrue(output.toString(StandardCharsets.UTF_8).contains("The breach check could not be completed."));
	}
}
