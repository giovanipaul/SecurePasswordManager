package org.example;

import org.example.crypto.CryptoService;
import org.example.service.VaultService;
import org.example.storage.VaultRepository;
import org.example.ui.ConsoleUI;

import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        Path vaultPath = Path.of("vault.json");

        CryptoService crypto = new CryptoService();
        VaultRepository repo = new VaultRepository(crypto);
        VaultService service = new VaultService();

        ConsoleUI ui = new ConsoleUI(repo, service);
        ui.run(vaultPath);
    }
}