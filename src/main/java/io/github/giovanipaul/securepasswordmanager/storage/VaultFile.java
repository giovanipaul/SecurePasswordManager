package io.github.giovanipaul.securepasswordmanager.storage;

public class VaultFile {
	public int version;
	public String kdf;
	public int iterations;
	public int keyLengthBits;
	public String cipher;

	// Base64 strings to make JSON easy
	public String saltB64;
	public String ivB64;
	public String ciphertextB64;

	public VaultFile() {
	}
}
