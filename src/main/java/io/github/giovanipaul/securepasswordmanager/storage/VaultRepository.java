package io.github.giovanipaul.securepasswordmanager.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.giovanipaul.securepasswordmanager.crypto.CryptoService;
import io.github.giovanipaul.securepasswordmanager.model.Vault;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

public class VaultRepository {

	static final int CURRENT_VERSION = 2;
	static final String KDF = "PBKDF2WithHmacSHA256";
	static final String CIPHER = "AES/GCM/NoPadding";
	private static final long MAX_VAULT_FILE_BYTES = 10L * 1024 * 1024;
	private static final int MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024;
	private static final int MIN_ITERATIONS = 100_000;
	private static final int MAX_ITERATIONS = 10_000_000;
	private final ObjectMapper mapper;
	private final CryptoService crypto;

	public VaultRepository(CryptoService crypto) {
		this.crypto = crypto;
		this.mapper = new ObjectMapper();
		this.mapper.registerModule(new JavaTimeModule());
	}

	public void initializeNewVault(Path path, char[] masterPassword) throws IOException, GeneralSecurityException {
		if (Files.exists(path)) {
			throw new IOException("Vault already exists: " + path);
		}
		save(path, masterPassword, new Vault());
	}

	public void save(Path path, char[] masterPassword, Vault vault) throws IOException, GeneralSecurityException {

		if (masterPassword == null || masterPassword.length == 0) {
			throw new IllegalArgumentException("Master password cannot be empty.");
		}
		if (vault == null) {
			throw new IllegalArgumentException("Vault cannot be null.");
		}

		byte[] salt = crypto.randomSalt();
		byte[] iv = crypto.randomIv();
		byte[] plaintext = null;
		byte[] ciphertext = null;
		Path absolutePath = path.toAbsolutePath();
		Path parent = Objects.requireNonNull(absolutePath.getParent(), "Vault path must have a parent.");
		Path tempPath = parent.resolve(absolutePath.getFileName() + ".tmp");

		try {
			Files.createDirectories(parent);
			SecretKey key = crypto.deriveKey(masterPassword, salt);
			plaintext = mapper.writeValueAsBytes(vault);

			VaultFile vf = new VaultFile();
			vf.version = CURRENT_VERSION;
			vf.kdf = KDF;
			vf.iterations = CryptoService.PBKDF2_ITERATIONS;
			vf.keyLengthBits = CryptoService.KEY_LEN_BITS;
			vf.cipher = CIPHER;
			vf.saltB64 = Base64.getEncoder().encodeToString(salt);
			vf.ivB64 = Base64.getEncoder().encodeToString(iv);
			ciphertext = crypto.encrypt(plaintext, key, iv, authenticatedMetadata(vf));
			vf.ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

			byte[] fileJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(vf)
					.getBytes(StandardCharsets.UTF_8);
			Files.write(tempPath, fileJson);
			moveIntoPlace(tempPath, absolutePath);
		} finally {
			Files.deleteIfExists(tempPath);
			CryptoService.wipe(plaintext);
			CryptoService.wipe(ciphertext);
			CryptoService.wipe(salt);
			CryptoService.wipe(iv);
		}
	}

	public Vault load(Path path, char[] masterPassword) throws IOException, GeneralSecurityException {

		if (!Files.exists(path)) {
			throw new IOException("Vault not found: " + path);
		}
		if (Files.size(path) > MAX_VAULT_FILE_BYTES) {
			throw new IOException("Vault file exceeds the maximum supported size.");
		}

		byte[] salt = null;
		byte[] iv = null;
		byte[] ciphertext = null;
		byte[] plaintext = null;
		try {
			String json = Files.readString(path, StandardCharsets.UTF_8);
			VaultFile vf = mapper.readValue(json, VaultFile.class);
			validateVaultFile(vf);

			salt = decode(vf.saltB64, "salt");
			iv = decode(vf.ivB64, "initialization vector");
			ciphertext = decode(vf.ciphertextB64, "ciphertext");
			if (salt.length != CryptoService.SALT_LEN || iv.length != CryptoService.GCM_IV_LEN
					|| ciphertext.length > MAX_CIPHERTEXT_BYTES) {
				throw new IOException("Vault file contains invalid encryption metadata.");
			}

			int iterations = vf.version == 1 ? CryptoService.PBKDF2_ITERATIONS : vf.iterations;
			int keyLengthBits = vf.version == 1 ? CryptoService.KEY_LEN_BITS : vf.keyLengthBits;
			SecretKey key = crypto.deriveKey(masterPassword, salt, iterations, keyLengthBits);
			byte[] associatedData = vf.version == 1 ? null : authenticatedMetadata(vf);
			plaintext = crypto.decrypt(ciphertext, key, iv, associatedData);
			return mapper.readValue(plaintext, Vault.class);
		} catch (IllegalArgumentException e) {
			throw new IOException("Vault file is corrupted or has invalid encoding.", e);
		} finally {
			CryptoService.wipe(plaintext);
			CryptoService.wipe(ciphertext);
			CryptoService.wipe(salt);
			CryptoService.wipe(iv);
		}
	}

	private static void validateVaultFile(VaultFile vaultFile) throws IOException {
		if (vaultFile == null || (vaultFile.version != 1 && vaultFile.version != CURRENT_VERSION)
				|| vaultFile.saltB64 == null || vaultFile.ivB64 == null || vaultFile.ciphertextB64 == null) {
			throw new IOException("Vault file is missing required encrypted data.");
		}
		if (vaultFile.version == CURRENT_VERSION && (!KDF.equals(vaultFile.kdf) || !CIPHER.equals(vaultFile.cipher)
				|| vaultFile.iterations < MIN_ITERATIONS || vaultFile.iterations > MAX_ITERATIONS
				|| vaultFile.keyLengthBits != CryptoService.KEY_LEN_BITS)) {
			throw new IOException("Vault file uses unsupported encryption parameters.");
		}
	}

	private static byte[] authenticatedMetadata(VaultFile vaultFile) {
		String metadata = vaultFile.version + "|" + vaultFile.kdf + "|" + vaultFile.iterations + "|"
				+ vaultFile.keyLengthBits + "|" + vaultFile.cipher;
		return metadata.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] decode(String value, String field) throws IOException {
		try {
			return Base64.getDecoder().decode(value);
		} catch (IllegalArgumentException e) {
			throw new IOException("Vault file has invalid " + field + ".", e);
		}
	}

	private static void moveIntoPlace(Path tempPath, Path destination) throws IOException {
		try {
			Files.move(tempPath, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
		} catch (java.nio.file.AtomicMoveNotSupportedException e) {
			Files.move(tempPath, destination, StandardCopyOption.REPLACE_EXISTING);
		}
	}
}
