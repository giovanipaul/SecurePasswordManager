package org.example.ui;

import org.example.crypto.CryptoService;
import org.example.model.Vault;
import org.example.model.VaultEntry;
import org.example.service.PasswordGenerator;
import org.example.service.PasswordPolicy;
import org.example.service.VaultService;
import org.example.service.VaultSession;
import org.example.storage.VaultRepository;

import javax.crypto.AEADBadTagException;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

public class ConsoleUI implements AutoCloseable {
    private static final Duration DEFAULT_AUTO_LOCK = Duration.ofMinutes(5);
    private static final String MASKED_PASSWORD = "********";

    private final VaultRepository repository;
    private final VaultService vaultService;
    private final PasswordGenerator passwordGenerator;
    private final VaultSession session;
    private final ClipboardService clipboard;
    private final Scanner scanner;
    private final PrintStream out;
    private final boolean systemIo;
    private final ScheduledExecutorService autoLockMonitor;

    private Path vaultPath;
    private Vault vault;
    private boolean dirty;
    private boolean fallbackPasswordWarningShown;

    public ConsoleUI(VaultRepository repository, VaultService vaultService) {
        this(repository, vaultService, System.in, System.out, DEFAULT_AUTO_LOCK);
    }

    ConsoleUI(VaultRepository repository, VaultService vaultService,
              InputStream input, PrintStream output, Duration autoLockTimeout) {
        this.repository = repository;
        this.vaultService = vaultService;
        this.passwordGenerator = new PasswordGenerator();
        this.session = new VaultSession(autoLockTimeout);
        this.clipboard = new ClipboardService();
        this.scanner = new Scanner(input);
        this.out = output;
        this.systemIo = input == System.in && output == System.out;
        this.autoLockMonitor = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory());
    }

    public void run(Path path) {
        this.vaultPath = path.toAbsolutePath();
        printWelcome();

        try {
            if (!openOrCreateVault()) return;
            startAutoLockMonitor();
            mainLoop();
        } finally {
            close();
        }
    }

    private boolean openOrCreateVault() {
        if (Files.exists(vaultPath)) {
            return openExistingVault();
        }
        return createNewVault();
    }

    private boolean createNewVault() {
        printInfo("No vault was found. Let's create one at:");
        out.println("  " + vaultPath);

        while (true) {
            char[] first = promptSecret("Create a master password: ");
            char[] confirmation = promptSecret("Confirm master password: ");
            try {
                String policyError = PasswordPolicy.validate(new String(first));
                if (policyError != null) {
                    printError(policyError);
                    out.println("Use at least 12 characters with uppercase, lowercase, a number, and a symbol.");
                    continue;
                }
                if (!Arrays.equals(first, confirmation)) {
                    printError("The passwords did not match. Please try again.");
                    continue;
                }

                repository.initializeNewVault(vaultPath, first);
                vault = new Vault();
                session.unlock(first);
                printSuccess("New encrypted vault created and unlocked.");
                return true;
            } catch (IOException | GeneralSecurityException e) {
                printError("The vault could not be created: " + readableMessage(e));
                return false;
            } finally {
                CryptoService.wipe(first);
                CryptoService.wipe(confirmation);
            }
        }
    }

    private boolean openExistingVault() {
        out.println("Vault found: " + vaultPath);
        for (int attemptNumber = 1; attemptNumber <= 3; attemptNumber++) {
            char[] attempt = promptSecret("Master password: ");
            try {
                vault = repository.load(vaultPath, attempt);
                session.unlock(attempt);
                printSuccess("Vault unlocked. " + vault.getEntries().size() + " saved credential(s) loaded.");
                return true;
            } catch (AEADBadTagException e) {
                printError("Incorrect master password or the encrypted vault was modified.");
            } catch (IOException e) {
                printError("The vault file could not be read. It may be missing or corrupted.");
                out.println("Details: " + readableMessage(e));
                return false;
            } catch (GeneralSecurityException e) {
                printError("The vault could not be decrypted: " + readableMessage(e));
                return false;
            } finally {
                CryptoService.wipe(attempt);
            }
            out.println("Attempts remaining: " + (3 - attemptNumber));
        }
        printError("Too many failed unlock attempts. The application will close.");
        return false;
    }

    private void mainLoop() {
        boolean running = true;
        while (running) {
            printMainMenu();
            String choice = promptLine("Choose an option: ").toLowerCase(Locale.ROOT);
            session.touch();
            out.println();

            try {
                running = handleChoice(choice);
            } catch (IllegalArgumentException e) {
                printError(e.getMessage());
            } catch (Exception e) {
                printError("That action could not be completed. Your saved vault was not replaced.");
                out.println("Details: " + readableMessage(e));
            }
        }
    }

    private boolean handleChoice(String choice) {
        return switch (choice) {
            case "1", "list", "ls" -> { listEntries(); yield true; }
            case "2", "add", "new" -> { addEntry(); yield true; }
            case "3", "view", "get" -> { viewEntry(); yield true; }
            case "4", "update", "edit" -> { updateEntry(); yield true; }
            case "5", "delete", "remove" -> { deleteEntry(); yield true; }
            case "6", "search", "find" -> { searchEntries(); yield true; }
            case "7", "generate", "gen" -> { generatePassword(); yield true; }
            case "8", "save" -> { saveVault(); yield true; }
            case "9", "clear" -> { clearVault(); yield true; }
            case "10" -> { toggleLock(); yield true; }
            case "lock" -> { lockSession(); yield true; }
            case "unlock" -> { unlockSession(); yield true; }
            case "11", "status" -> { printStatus(); yield true; }
            case "12", "help", "?" -> { printHelp(); yield true; }
            case "0", "exit", "quit" -> !exitApplication();
            case "" -> true;
            default -> {
                printError("Unknown option: '" + choice + "'.");
                out.println("Try a menu number, or a command such as 'list', 'add', 'help', or 'exit'.");
                yield true;
            }
        };
    }

    private void listEntries() {
        if (!ensureUnlocked()) return;
        List<VaultEntry> entries = vaultService.list(vault);
        printHeading("Saved Credentials");
        if (entries.isEmpty()) {
            out.println("No credentials are saved yet. Choose 2 to add one.");
            return;
        }
        printEntryTable(entries);
    }

    private void addEntry() {
        if (!ensureUnlocked()) return;
        printHeading("Add Credential");
        String site = promptRequired("Service or website: ");
        String username = promptRequired("Username or email: ");
        char[] passwordChars = promptNewCredentialPassword();
        try {
            String notes = promptLine("Notes (optional): ");
            VaultEntry entry = vaultService.add(vault, site, username,
                    new String(passwordChars), notes);
            dirty = true;
            if (saveVault()) {
                printSuccess("Credential added for " + entry.getSite() + ".");
            }
        } finally {
            CryptoService.wipe(passwordChars);
        }
    }

    private char[] promptNewCredentialPassword() {
        while (true) {
            out.println("1) Enter a password");
            out.println("2) Generate a strong password");
            String method = promptLine("Choose 1 or 2: ");
            char[] password;
            if (method.equals("2")) {
                int length = promptInt("Password length (12-128, default 20): ", 12, 128, 20);
                password = passwordGenerator.generate(length, true, true).toCharArray();
                printSuccess("A strong password was generated (kept hidden).");
                if (confirm("Copy it to the clipboard now?")) {
                    copySecret(new String(password));
                }
            } else if (method.equals("1")) {
                password = promptSecret("Password: ");
            } else {
                printError("Please choose 1 or 2.");
                continue;
            }

            String policyError = PasswordPolicy.validate(new String(password));
            if (policyError == null) return password;
            CryptoService.wipe(password);
            printError(policyError);
        }
    }

    private void viewEntry() {
        if (!ensureUnlocked()) return;
        VaultEntry entry = selectEntry("View Credential");
        if (entry == null) return;

        out.println("Service:  " + entry.getSite());
        out.println("Username: " + entry.getUsername());
        out.println("Password: " + MASKED_PASSWORD);
        out.println("Notes:    " + emptyAsDash(entry.getNotes()));
        out.println();
        out.println("1) Reveal password");
        out.println("2) Copy password");
        out.println("0) Back to main menu");
        String action = promptLine("Choose an option: ");
        if (action.equals("1")) {
            if (verifyMasterPassword()) {
                out.println("Password: " + entry.getPassword());
                out.println("Reminder: clear your terminal history/screen if others can view it.");
            }
        } else if (action.equals("2")) {
            if (verifyMasterPassword()) copySecret(entry.getPassword());
        } else if (!action.equals("0")) {
            printError("Unknown option. Returning to the main menu.");
        }
    }

    private void updateEntry() {
        if (!ensureUnlocked()) return;
        VaultEntry entry = selectEntry("Update Credential");
        if (entry == null) return;

        out.println("Press Enter to keep the current value. Enter '-' to clear notes.");
        String site = blankToNull(promptLine("Service [" + entry.getSite() + "]: "));
        String username = blankToNull(promptLine("Username [" + entry.getUsername() + "]: "));
        String notesInput = promptLine("Notes [" + emptyAsDash(entry.getNotes()) + "]: ");
        String notes = notesInput.equals("-") ? "" : blankToNull(notesInput);
        String password = null;

        if (confirm("Change the password?")) {
            char[] passwordChars = promptNewCredentialPassword();
            try {
                password = new String(passwordChars);
            } finally {
                CryptoService.wipe(passwordChars);
            }
        }

        boolean changed = site != null || username != null || notes != null || password != null;
        if (!changed) {
            printInfo("No changes were entered.");
            return;
        }

        vaultService.update(vault, entry.getId(), site, username, password, notes);
        dirty = true;
        if (saveVault()) printSuccess("Credential updated.");
    }

    private void deleteEntry() {
        if (!ensureUnlocked()) return;
        VaultEntry entry = selectEntry("Delete Credential");
        if (entry == null) return;
        if (!confirm("Delete the credential for " + entry.getSite() + " / " + entry.getUsername() + "?")) {
            printInfo("Delete canceled.");
            return;
        }

        if (vaultService.delete(vault, entry.getId())) {
            dirty = true;
            if (saveVault()) printSuccess("Credential deleted.");
        }
    }

    private void searchEntries() {
        if (!ensureUnlocked()) return;
        printHeading("Search Credentials");
        String query = promptRequired("Search service, username, or notes: ");
        List<VaultEntry> matches = vaultService.search(vault, query);
        if (matches.isEmpty()) {
            printInfo("No matching credentials were found.");
        } else {
            printEntryTable(matches);
        }
    }

    private void generatePassword() {
        if (!ensureUnlocked()) return;
        printHeading("Password Generator");
        int length = promptInt("Length (8-128, default 20): ", 8, 128, 20);
        boolean symbols = confirmDefaultYes("Include symbols?");
        boolean avoidAmbiguous = confirmDefaultYes("Avoid look-alike characters (O, 0, I, l, 1)?");
        char[] password = passwordGenerator.generate(length, symbols, avoidAmbiguous).toCharArray();
        try {
            printSuccess("Password generated and kept hidden.");
            out.println("1) Reveal once");
            out.println("2) Copy to clipboard");
            out.println("0) Discard and return");
            String action = promptLine("Choose an option: ");
            if (action.equals("1")) out.println("Generated password: " + new String(password));
            else if (action.equals("2")) copySecret(new String(password));
            else printInfo("Generated password discarded.");
        } finally {
            CryptoService.wipe(password);
        }
    }

    private boolean saveVault() {
        if (!ensureUnlocked()) return false;
        char[] master = null;
        try {
            master = session.copyMasterPassword();
            repository.save(vaultPath, master, vault);
            dirty = false;
            printSuccess("Vault saved securely.");
            return true;
        } catch (IOException | GeneralSecurityException e) {
            dirty = true;
            printError("The vault could not be saved. The previous file was left unchanged.");
            out.println("Details: " + readableMessage(e));
            return false;
        } finally {
            CryptoService.wipe(master);
        }
    }

    private void clearVault() {
        if (!ensureUnlocked()) return;
        printHeading("Clear Entire Vault");
        if (vault.getEntries().isEmpty()) {
            printInfo("The vault is already empty.");
            return;
        }
        out.println("This will permanently delete all " + vault.getEntries().size() + " saved credential(s).");
        String confirmation = promptLine("Type CLEAR to continue: ");
        if (!confirmation.equals("CLEAR")) {
            printInfo("Clear canceled.");
            return;
        }
        int removed = vaultService.clear(vault);
        dirty = true;
        if (saveVault()) printSuccess(removed + " credential(s) deleted.");
    }

    private void toggleLock() {
        if (session.isUnlocked()) {
            lockSession();
        } else {
            unlockSession();
        }
    }

    private void lockSession() {
        if (!session.isUnlocked()) {
            printInfo("The vault is already locked.");
            return;
        }
        session.lock();
        printInfo("Vault locked. Sensitive actions are unavailable until you unlock it.");
    }

    private boolean ensureUnlocked() {
        if (session.isUnlocked()) return true;
        printInfo("The vault is locked.");
        return unlockSession();
    }

    private boolean unlockSession() {
        if (session.isUnlocked()) {
            printInfo("The vault is already unlocked.");
            return true;
        }
        char[] attempt = promptSecret("Master password: ");
        try {
            repository.load(vaultPath, attempt);
            session.unlock(attempt);
            printSuccess("Vault unlocked.");
            return true;
        } catch (Exception e) {
            printError("Unlock failed. Check the master password and vault file.");
            return false;
        } finally {
            CryptoService.wipe(attempt);
        }
    }

    private boolean verifyMasterPassword() {
        char[] attempt = promptSecret("Re-enter the master password: ");
        try {
            repository.load(vaultPath, attempt);
            session.touch();
            return true;
        } catch (Exception e) {
            printError("Verification failed. The password was not revealed or copied.");
            return false;
        } finally {
            CryptoService.wipe(attempt);
        }
    }

    private void printStatus() {
        boolean unlocked = session.isUnlocked();
        printHeading("Vault Status");
        out.println("State:            " + (unlocked ? "UNLOCKED" : "LOCKED"));
        out.println("Saved entries:    " + vault.getEntries().size());
        out.println("Unsaved changes:  " + (dirty ? "YES" : "NO"));
        out.println("Auto-lock timeout: " + session.timeoutSeconds() + " seconds");
        out.println("Clipboard clear:   " + clipboard.clearDelaySeconds() + " seconds");
        out.println("Vault file:        " + vaultPath);
    }

    private boolean exitApplication() {
        if (dirty) {
            if (confirmDefaultYes("You have unsaved changes. Save before exiting?")) {
                if (!saveVault() && !confirm("Saving failed. Exit anyway?")) return false;
            } else if (!confirm("Exit and discard unsaved changes?")) {
                return false;
            }
        }
        printInfo("Vault locked. Goodbye.");
        return true;
    }

    private VaultEntry selectEntry(String heading) {
        List<VaultEntry> entries = vaultService.list(vault);
        printHeading(heading);
        if (entries.isEmpty()) {
            printInfo("No credentials are saved yet.");
            return null;
        }
        printEntryTable(entries);
        int selection = promptInt("Select an entry number (0 to cancel): ", 0, entries.size(), 0);
        return selection == 0 ? null : entries.get(selection - 1);
    }

    private void printEntryTable(List<VaultEntry> entries) {
        out.printf("%-4s %-26s %-32s %s%n", "No.", "Service", "Username", "Password");
        out.println("---- -------------------------- -------------------------------- --------");
        for (int i = 0; i < entries.size(); i++) {
            VaultEntry entry = entries.get(i);
            out.printf("%-4d %-26s %-32s %s%n", i + 1,
                    truncate(entry.getSite(), 26), truncate(entry.getUsername(), 32), MASKED_PASSWORD);
        }
    }

    private void printWelcome() {
        out.println();
        out.println("============================================================");
        out.println("                 SECURE PASSWORD MANAGER");
        out.println("============================================================");
        out.println("Encrypted local credential storage for personal use.");
        out.println("Passwords stay masked unless you explicitly reveal them.");
        out.println();
    }

    private void printMainMenu() {
        out.println();
        out.println("-------------------------- MAIN MENU -------------------------");
        out.println("  1. List credentials        7. Generate password");
        out.println("  2. Add credential          8. Save vault");
        out.println("  3. View / reveal / copy    9. Clear vault");
        out.println("  4. Update credential      10. Lock or unlock");
        out.println("  5. Delete credential      11. Vault status");
        out.println("  6. Search credentials     12. Help");
        out.println("  0. Save and exit");
        out.println("--------------------------------------------------------------");
    }

    private void printHelp() {
        printHeading("Help");
        out.println("You can enter a menu number or the command shown below:");
        out.println("  list       Show saved services and usernames; passwords remain masked.");
        out.println("  add        Save a new credential using a typed or generated password.");
        out.println("  view       Select an entry to view, reveal, or copy its password.");
        out.println("  update     Change selected credential fields; blank keeps the old value.");
        out.println("  delete     Delete one selected credential after confirmation.");
        out.println("  search     Find entries by service, username, or notes.");
        out.println("  generate   Create a strong password and reveal or copy it once.");
        out.println("  save       Encrypt and save the current vault immediately.");
        out.println("  clear      Delete every entry only after typing CLEAR.");
        out.println("  lock       Clear the in-memory master password and block sensitive actions.");
        out.println("  unlock     Reopen a locked session with the master password.");
        out.println("  status     Show lock, save, auto-lock, clipboard, and file information.");
        out.println("  exit       Save if needed, lock the vault, and close the application.");
        out.println();
        out.println("Examples: enter '2' to add, 'list' to browse, or '?' for this screen.");
    }

    private char[] promptSecret(String prompt) {
        Console console = System.console();
        if (console != null && systemIo) {
            return console.readPassword("%s", prompt);
        }
        if (!fallbackPasswordWarningShown) {
            out.println("Note: this terminal cannot hide typed input; make sure no one can see your screen.");
            fallbackPasswordWarningShown = true;
        }
        out.print(prompt);
        return scanner.nextLine().toCharArray();
    }

    private String promptRequired(String prompt) {
        while (true) {
            String value = promptLine(prompt);
            if (!value.isBlank()) return value.trim();
            printError("This field cannot be empty.");
        }
    }

    private String promptLine(String prompt) {
        out.print(prompt);
        if (!scanner.hasNextLine()) return "exit";
        return scanner.nextLine().trim();
    }

    private int promptInt(String prompt, int minimum, int maximum, int defaultValue) {
        while (true) {
            String input = promptLine(prompt);
            if (input.isBlank()) return defaultValue;
            try {
                int value = Integer.parseInt(input);
                if (value >= minimum && value <= maximum) return value;
            } catch (NumberFormatException ignored) {
                // Handled by the readable message below.
            }
            printError("Enter a whole number from " + minimum + " to " + maximum + ".");
        }
    }

    private boolean confirm(String question) {
        String answer = promptLine(question + " (y/N): ").toLowerCase(Locale.ROOT);
        return answer.equals("y") || answer.equals("yes");
    }

    private boolean confirmDefaultYes(String question) {
        String answer = promptLine(question + " (Y/n): ").toLowerCase(Locale.ROOT);
        return answer.isBlank() || answer.equals("y") || answer.equals("yes");
    }

    private void copySecret(String secret) {
        if (clipboard.copy(secret)) {
            printSuccess("Copied to clipboard. It will be cleared in "
                    + clipboard.clearDelaySeconds() + " seconds.");
        } else {
            printError("Clipboard access is unavailable in this environment. Choose reveal instead.");
        }
    }

    private void startAutoLockMonitor() {
        autoLockMonitor.scheduleAtFixedRate(() -> {
            if (session.lockIfExpired()) {
                out.println();
                printInfo("Vault automatically locked after " + session.timeoutSeconds()
                        + " seconds of inactivity.");
            }
        }, 1, 1, TimeUnit.SECONDS);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String emptyAsDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private static String truncate(String value, int width) {
        String safe = value == null ? "" : value;
        return safe.length() <= width ? safe : safe.substring(0, width - 3) + "...";
    }

    private static String readableMessage(Exception error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
    }

    private void printHeading(String text) {
        out.println("--- " + text + " ---");
    }

    private void printSuccess(String text) {
        out.println("[OK] " + text);
    }

    private void printInfo(String text) {
        out.println("[INFO] " + text);
    }

    private void printError(String text) {
        out.println("[ERROR] " + text);
    }

    @Override
    public void close() {
        autoLockMonitor.shutdownNow();
        clipboard.close();
        session.close();
    }

    private static final class DaemonThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "password-manager-auto-lock");
            thread.setDaemon(true);
            return thread;
        }
    }
}
