package org.example.storage;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.example.crypto.CryptoService;
import org.example.model.Vault;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class VaultRepository {

    private final ObjectMapper mapper;
    private final CryptoService crypto;

    public VaultRepository(CryptoService crypto) {
        this.crypto = crypto;
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
    }

    public void initializeNewVault(Path path, char[] masterPassword)
            throws IOException, GeneralSecurityException {
        if (Files.exists(path)) {
            throw new IOException("Vault already exists: " + path);
        }
        save(path, masterPassword, new Vault());
    }

    public void save(Path path, char[] masterPassword, Vault vault)
            throws IOException, GeneralSecurityException {

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
        Path parent = absolutePath.getParent();
        Path tempPath = parent.resolve(absolutePath.getFileName() + ".tmp");

        try {
            if (parent != null) Files.createDirectories(parent);
            SecretKey key = crypto.deriveKey(masterPassword, salt);
            plaintext = mapper.writeValueAsBytes(vault);
            ciphertext = crypto.encrypt(plaintext, key, iv);

            VaultFile vf = new VaultFile();
            vf.saltB64 = Base64.getEncoder().encodeToString(salt);
            vf.ivB64 = Base64.getEncoder().encodeToString(iv);
            vf.ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

            byte[] fileJson = mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(vf)
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

    public Vault load(Path path, char[] masterPassword)
            throws IOException, GeneralSecurityException {

        if (!Files.exists(path)) {
            throw new IOException("Vault not found: " + path);
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
            if (salt.length != CryptoService.SALT_LEN || iv.length != CryptoService.GCM_IV_LEN) {
                throw new IOException("Vault file contains invalid encryption metadata.");
            }

            SecretKey key = crypto.deriveKey(masterPassword, salt);
            plaintext = crypto.decrypt(ciphertext, key, iv);
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
        if (vaultFile == null || vaultFile.version != 1
                || vaultFile.saltB64 == null || vaultFile.ivB64 == null
                || vaultFile.ciphertextB64 == null) {
            throw new IOException("Vault file is missing required encrypted data.");
        }
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
            Files.move(tempPath, destination,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tempPath, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
