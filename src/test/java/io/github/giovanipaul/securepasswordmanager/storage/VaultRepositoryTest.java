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
		assertTrue(stored.contains("\"iterations\" : 600000"));
		if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
			assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
					Files.getPosixFilePermissions(path));
		}
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
		SecretKey key = crypto.deriveKey(master, salt, 210_000, CryptoService.KEY_LEN_BITS);
		byte[] ciphertext = crypto.encrypt(mapper.writeValueAsBytes(vault), key, iv);

		VaultFile legacy = new VaultFile();
		legacy.version = 1;
		legacy.saltB64 = Base64.getEncoder().encodeToString(salt);
		legacy.ivB64 = Base64.getEncoder().encodeToString(iv);
		legacy.ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);
		mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), legacy);

		VaultRepository repository = new VaultRepository(crypto);
		byte[] original = Files.readAllBytes(path);
		assertThrows(AEADBadTagException.class, () -> repository.load(path, "WrongPassword1!".toCharArray()));
		assertArrayEquals(original, Files.readAllBytes(path));
		Vault loaded = repository.load(path, master);
		assertEquals("Legacy", loaded.getEntries().get(0).getSite());
		assertTrue(repository.needsKeyDerivationUpgrade(path));
		repository.save(path, master, loaded);
		assertFalse(repository.needsKeyDerivationUpgrade(path));
		assertEquals(600_000, mapper.readTree(path.toFile()).get("iterations").asInt());
		assertEquals("Legacy", repository.load(path, master).getEntries().get(0).getSite());
	}

	@Test
	void upgradesLegacyVersionTwoAndPreservesOriginalWhenEncryptionFails() throws Exception {
		Path path = tempDir.resolve("legacy-v2.json");
		CryptoService crypto = new CryptoService();
		ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
		char[] master = "StrongMaster1!".toCharArray();
		Vault vault = new Vault();
		new VaultService().add(vault, "Legacy V2", "user", "CredentialPass1!", "");
		byte[] salt = crypto.randomSalt();
		byte[] iv = crypto.randomIv();
		VaultFile legacy = new VaultFile();
		legacy.version = 2;
		legacy.kdf = VaultRepository.KDF;
		legacy.iterations = 210_000;
		legacy.keyLengthBits = CryptoService.KEY_LEN_BITS;
		legacy.cipher = VaultRepository.CIPHER;
		legacy.saltB64 = Base64.getEncoder().encodeToString(salt);
		legacy.ivB64 = Base64.getEncoder().encodeToString(iv);
		byte[] metadata = ("2|" + legacy.kdf + "|210000|256|" + legacy.cipher)
				.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		SecretKey key = crypto.deriveKey(master, salt, 210_000, 256);
		legacy.ciphertextB64 = Base64.getEncoder()
				.encodeToString(crypto.encrypt(mapper.writeValueAsBytes(vault), key, iv, metadata));
		mapper.writeValue(path.toFile(), legacy);

		VaultRepository repository = new VaultRepository(crypto);
		Vault loaded = repository.load(path, master);
		assertTrue(repository.needsKeyDerivationUpgrade(path));
		byte[] original = Files.readAllBytes(path);
		CryptoService failingCrypto = new CryptoService() {
			@Override
			public byte[] encrypt(byte[] plaintext, SecretKey secretKey, byte[] nonce, byte[] aad)
					throws java.security.GeneralSecurityException {
				throw new java.security.GeneralSecurityException("Simulated encryption failure");
			}
		};
		assertThrows(java.security.GeneralSecurityException.class,
				() -> new VaultRepository(failingCrypto).save(path, master, loaded));
		assertArrayEquals(original, Files.readAllBytes(path));
		assertEquals("Legacy V2", repository.load(path, master).getEntries().get(0).getSite());
		try (var files = Files.list(tempDir)) {
			assertEquals(1, files.count());
		}
		repository.save(path, master, loaded);
		assertFalse(repository.needsKeyDerivationUpgrade(path));
		assertEquals("Legacy V2", repository.load(path, master).getEntries().get(0).getSite());
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
