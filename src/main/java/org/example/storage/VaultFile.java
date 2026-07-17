package org.example.storage;

public class VaultFile {
    public int version = 1;

    // Base64 strings to make JSON easy
    public String saltB64;
    public String ivB64;
    public String ciphertextB64;

    public VaultFile() {}
}