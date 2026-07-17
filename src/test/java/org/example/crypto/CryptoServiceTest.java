package org.example.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {
    private final CryptoService crypto = new CryptoService();

    @Test
    void encryptsAndDecryptsRoundTrip() throws Exception {
        char[] master = "StrongMaster1!".toCharArray();
        byte[] salt = crypto.randomSalt();
        byte[] iv = crypto.randomIv();
        SecretKey key = crypto.deriveKey(master, salt);
        byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = crypto.encrypt(plaintext, key, iv);
        assertFalse(java.util.Arrays.equals(plaintext, ciphertext));
        assertArrayEquals(plaintext, crypto.decrypt(ciphertext, key, iv));
    }

    @Test
    void rejectsWrongMasterPassword() throws Exception {
        byte[] salt = crypto.randomSalt();
        byte[] iv = crypto.randomIv();
        SecretKey correct = crypto.deriveKey("CorrectMaster1!".toCharArray(), salt);
        SecretKey wrong = crypto.deriveKey("IncorrectMaster1!".toCharArray(), salt);
        byte[] encrypted = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), correct, iv);

        assertThrows(AEADBadTagException.class, () -> crypto.decrypt(encrypted, wrong, iv));
    }
}
