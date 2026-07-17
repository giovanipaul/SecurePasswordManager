package org.example.ui;

import org.example.crypto.CryptoService;
import org.example.service.VaultService;
import org.example.storage.VaultRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class ConsoleUITest {
    @TempDir Path tempDir;

    @Test
    void firstRunCreatesVaultAndDisplaysWelcomeMenu() throws Exception {
        Path vaultPath = tempDir.resolve("vault.json");
        String input = String.join(System.lineSeparator(),
                "StrongMaster1!", "StrongMaster1!", "0") + System.lineSeparator();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        VaultRepository repository = new VaultRepository(new CryptoService());

        ConsoleUI ui = new ConsoleUI(repository, new VaultService(),
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(output), Duration.ofMinutes(5));
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
        String input = String.join(System.lineSeparator(),
                "StrongMaster1!", "StrongMaster1!",
                "2", "Example", "giovani", "1", "CredentialPass1!", "portfolio",
                "0") + System.lineSeparator();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        VaultRepository repository = new VaultRepository(new CryptoService());

        ConsoleUI ui = new ConsoleUI(repository, new VaultService(),
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(output), Duration.ofMinutes(5));
        ui.run(vaultPath);

        var loaded = repository.load(vaultPath, "StrongMaster1!".toCharArray());
        assertEquals(1, loaded.getEntries().size());
        assertEquals("Example", loaded.getEntries().get(0).getSite());
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("Vault saved securely"));
    }

    @Test
    void invalidCommandShowsExamplesInsteadOfCrashing() {
        Path vaultPath = tempDir.resolve("vault.json");
        String input = String.join(System.lineSeparator(),
                "StrongMaster1!", "StrongMaster1!", "not-a-command", "0")
                + System.lineSeparator();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        ConsoleUI ui = new ConsoleUI(new VaultRepository(new CryptoService()), new VaultService(),
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(output), Duration.ofMinutes(5));
        ui.run(vaultPath);

        String terminal = output.toString(StandardCharsets.UTF_8);
        assertTrue(terminal.contains("Unknown option"));
        assertTrue(terminal.contains("'list', 'add', 'help', or 'exit'"));
    }
}
