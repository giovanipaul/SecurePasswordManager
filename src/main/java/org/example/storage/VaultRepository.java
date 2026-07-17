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

        byte[] salt = crypto.randomSalt();
        byte[] iv = crypto.randomIv();

        SecretKey key = crypto.deriveKey(masterPassword, salt);

        byte[] plaintext = mapper.writeValueAsBytes(vault);
        byte[] ciphertext = crypto.encrypt(plaintext, key, iv);

        VaultFile vf = new VaultFile();
        vf.saltB64 = Base64.getEncoder().encodeToString(salt);
        vf.ivB64 = Base64.getEncoder().encodeToString(iv);
        vf.ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

        byte[] fileJson = mapper.writerWithDefaultPrettyPrinter()
                .writeValueAsString(vf)
                .getBytes(StandardCharsets.UTF_8);

        Files.write(path, fileJson);

        CryptoService.wipe(plaintext);
        CryptoService.wipe(ciphertext);
        CryptoService.wipe(salt);
        CryptoService.wipe(iv);
    }

    public Vault load(Path path, char[] masterPassword)
            throws IOException, GeneralSecurityException {

        if (!Files.exists(path)) {
            throw new IOException("Vault not found: " + path);
        }

        String json = Files.readString(path, StandardCharsets.UTF_8);
        VaultFile vf = mapper.readValue(json, VaultFile.class);

        byte[] salt = Base64.getDecoder().decode(vf.saltB64);
        byte[] iv = Base64.getDecoder().decode(vf.ivB64);
        byte[] ciphertext = Base64.getDecoder().decode(vf.ciphertextB64);

        SecretKey key = crypto.deriveKey(masterPassword, salt);

        byte[] plaintext = crypto.decrypt(ciphertext, key, iv);
        Vault vault = mapper.readValue(plaintext, Vault.class);

        CryptoService.wipe(plaintext);
        CryptoService.wipe(ciphertext);
        CryptoService.wipe(salt);
        CryptoService.wipe(iv);

        return vault;
    }
}