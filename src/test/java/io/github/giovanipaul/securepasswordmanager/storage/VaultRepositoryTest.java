package io.github.giovanipaul.securepasswordmanager.storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.giovanipaul.securepasswordmanager.crypto.CryptoService;
import io.github.giovanipaul.securepasswordmanager.model.Vault;
import io.github.giovanipaul.securepasswordmanager.service.VaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class VaultRepositoryTest {
	@TempDir
	Path tempDir;

	@Test
	void savesAndLoadsEncryptedVaultWithoutPlaintext() throws Exception {
		Path path = tempDir.resolve("vault.json");
		VaultRepository repository = new VaultRepository(new CryptoService());
		Vault vault = new Vault();
		new VaultService().add(vault, "Example", "giovani", "SecretPass1!", "private note");
		char[] master = "StrongMaster1!".toCharArray();

		repository.save(path, master, vault);
		String stored = Files.readString(path);
		assertTrue(stored.contains("\"version\" : 2"));
		assertTrue(stored.contains("\"kdf\" : \"PBKDF2WithHmacSHA256\""));
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

		assertThrows(java.io.IOException.class, () -> repository.load(path, "StrongMaster1!".toCharArray()));
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

	@Test
	void loadsLegacyVersionOneVault() throws Exception {
		Path path = tempDir.resolve("legacy-vault.json");
		CryptoService crypto = new CryptoService();
		ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
		Vault vault = new Vault();
		new VaultService().add(vault, "Legacy", "user", "CredentialPass1!", "");
		char[] master = "StrongMaster1!".toCharArray();
		byte[] salt = crypto.randomSalt();
		byte[] iv = crypto.randomIv();
		SecretKey key = crypto.deriveKey(master, salt);
		byte[] ciphertext = crypto.encrypt(mapper.writeValueAsBytes(vault), key, iv);

		VaultFile legacy = new VaultFile();
		legacy.version = 1;
		legacy.saltB64 = Base64.getEncoder().encodeToString(salt);
		legacy.ivB64 = Base64.getEncoder().encodeToString(iv);
		legacy.ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);
		mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), legacy);

		Vault loaded = new VaultRepository(crypto).load(path, master);
		assertEquals("Legacy", loaded.getEntries().get(0).getSite());
	}

	@Test
	void rejectsAuthenticatedMetadataModification() throws Exception {
		Path path = tempDir.resolve("vault.json");
		VaultRepository repository = new VaultRepository(new CryptoService());
		char[] master = "StrongMaster1!".toCharArray();
		repository.save(path, master, new Vault());

		ObjectMapper mapper = new ObjectMapper();
		JsonNode root = mapper.readTree(path.toFile());
		((com.fasterxml.jackson.databind.node.ObjectNode) root).put("iterations", CryptoService.PBKDF2_ITERATIONS + 1);
		mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), root);

		assertThrows(AEADBadTagException.class, () -> repository.load(path, master));
	}

	@Test
	void rejectsOversizedVaultBeforeParsing() throws Exception {
		Path path = tempDir.resolve("oversized.json");
		Files.write(path, new byte[10 * 1024 * 1024 + 1]);

		VaultRepository repository = new VaultRepository(new CryptoService());
		java.io.IOException error = assertThrows(java.io.IOException.class,
				() -> repository.load(path, "StrongMaster1!".toCharArray()));
		assertTrue(error.getMessage().contains("maximum supported size"));
	}
}
