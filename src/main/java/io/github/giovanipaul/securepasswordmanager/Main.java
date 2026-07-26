package io.github.giovanipaul.securepasswordmanager;

import io.github.giovanipaul.securepasswordmanager.crypto.CryptoService;
import io.github.giovanipaul.securepasswordmanager.service.VaultService;
import io.github.giovanipaul.securepasswordmanager.storage.VaultRepository;
import io.github.giovanipaul.securepasswordmanager.ui.ConsoleUI;

import java.nio.file.Path;

public class Main {
	public static void main(String[] args) {
		Path vaultPath = args.length > 0 ? Path.of(args[0]) : Path.of("vault.json");

		CryptoService crypto = new CryptoService();
		VaultRepository repo = new VaultRepository(crypto);
		VaultService service = new VaultService();

		try (ConsoleUI ui = new ConsoleUI(repo, service)) {
			ui.run(vaultPath);
		} catch (Exception e) {
			System.err.println("The password manager could not start: "
					+ (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
		}
	}
}
