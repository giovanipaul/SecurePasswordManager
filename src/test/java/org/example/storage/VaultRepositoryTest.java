package org.example.storage;

import org.example.crypto.CryptoService;
import org.example.model.Vault;
import org.example.service.VaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class VaultRepositoryTest {
    @TempDir Path tempDir;

    @Test
    void savesAndLoadsEncryptedVaultWithoutPlaintext() throws Exception {
        Path path = tempDir.resolve("vault.json");
        VaultRepository repository = new VaultRepository(new CryptoService());
        Vault vault = new Vault();
        new VaultService().add(vault, "Example", "giovani", "SecretPass1!", "private note");
        char[] master = "StrongMaster1!".toCharArray();

        repository.save(path, master, vault);
        String stored = Files.readString(path);
        assertFalse(stored.contains("SecretPass1!"));
        assertFalse(stored.contains("giovani"));
        assertEquals("Example", repository.load(path, master).getEntries().get(0).getSite());
        assertFalse(Files.exists(tempDir.resolve("vault.json.tmp")));
    }

    @Test
    void corruptedFileProducesReadableIoFailure() throws Exception {
        Path path = tempDir.resolve("vault.json");
        Files.writeString(path, "{ not valid json }");
        VaultRepository repository = new VaultRepository(new CryptoService());

        assertThrows(java.io.IOException.class,
                () -> repository.load(path, "StrongMaster1!".toCharArray()));
    }

    @Test
    void doesNotOverwriteExistingVaultDuringInitialize() throws Exception {
        Path path = tempDir.resolve("vault.json");
        Files.writeString(path, "original");
        VaultRepository repository = new VaultRepository(new CryptoService());
        assertThrows(java.io.IOException.class,
                () -> repository.initializeNewVault(path, "StrongMaster1!".toCharArray()));
        assertEquals("original", Files.readString(path));
    }
}
