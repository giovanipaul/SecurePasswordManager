package org.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoService {

    private static final SecureRandom RNG = new SecureRandom();

    // KDF settings (tunable)
    public static final int SALT_LEN = 16;
    public static final int PBKDF2_ITERATIONS = 210_000;
    public static final int KEY_LEN_BITS = 256;

    // AES-GCM settings
    public static final int GCM_IV_LEN = 12;      // recommended 12 bytes
    public static final int GCM_TAG_LEN_BITS = 128;

    public byte[] randomSalt() {
        byte[] salt = new byte[SALT_LEN];
        RNG.nextBytes(salt);
        return salt;
    }

    public byte[] randomIv() {
        byte[] iv = new byte[GCM_IV_LEN];
        RNG.nextBytes(iv);
        return iv;
    }

    public SecretKey deriveKey(char[] masterPassword, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, KEY_LEN_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_LEN_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcm);
        return cipher.doFinal(plaintext); // includes authentication tag
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_LEN_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcm);
        return cipher.doFinal(ciphertext); // throws AEADBadTagException if wrong password/tampered
    }

    // Best-effort memory wipe helpers
    public static void wipe(byte[] arr) {
        if (arr != null) Arrays.fill(arr, (byte) 0);
    }

    public static void wipe(char[] arr) {
        if (arr != null) Arrays.fill(arr, '\0');
    }
}