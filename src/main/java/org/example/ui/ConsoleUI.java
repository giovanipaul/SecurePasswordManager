package org.example.ui;

import org.example.model.Vault;
import org.example.model.VaultEntry;
import org.example.service.VaultService;
import org.example.storage.VaultRepository;
import org.example.service.PasswordGenerator;
import org.example.service.PasswordPolicy;
import java.util.concurrent.atomic.AtomicInteger;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicLong;
import org.example.crypto.CryptoService;
import java.nio.file.Path;
import java.util.Optional;
import java.util.Scanner;

public class ConsoleUI {

    private final VaultRepository repo;
    private final VaultService service;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory());
    private final PasswordGenerator generator = new PasswordGenerator();
    private final AtomicInteger failedUnlocks = new AtomicInteger(0);
    private static final int MAX_FAILS_BEFORE_DELAY = 5;
    private static final int BASE_DELAY_SECONDS = 30;
    // Auto-lock config
    private static final long AUTO_LOCK_SECONDS = 300; // 5 minutes (change if you want)
    private final AtomicLong lastActivityMs = new AtomicLong(System.currentTimeMillis());
    // Master password stored only while "unlocked" (wiped on lock)
    private char[] masterInMemory = null;
    // Auto-lock task handle
    private ScheduledFuture<?> autoLockTask;

    public ConsoleUI(VaultRepository repo, VaultService service) {
        this.repo = repo;
        this.service = service;
    }

    public void run(Path vaultPath) throws Exception {
        try (Scanner sc = new Scanner(System.in)) {
            char[] master = promptPassword(sc, "Master password: ");

            touchActivity();

            Vault vault;
            if (!vaultPath.toFile().exists()) {
                System.out.println("No vault found. Creating a new one.");
                // Need a master password to create the vault
                if (!unlock(vaultPath, sc)) {
                    System.out.println("Cannot create vault without a master password.");
                    return;
                }
                repo.initializeNewVault(vaultPath, masterInMemory);
                vault = repo.load(vaultPath, masterInMemory);
                System.out.println("Created new vault: " + vaultPath.toAbsolutePath());
            } else {
                // Unlock to load at startup (or you can choose to start locked—this is simplest)
                if (!unlock(vaultPath, sc)) return;
                vault = repo.load(vaultPath, masterInMemory);
                System.out.println("Vault loaded. Entries: " + vault.getEntries().size());
            }

            boolean dirty = false;

// Start the auto-lock background check
            startAutoLockMonitor();

            printHelp();
            while (true) {
                System.out.print("\ncmd> ");
                String line = sc.nextLine().trim();
                touchActivity();
                if (line.isEmpty()) continue;

                String[] parts = line.split("\\s+");
                String cmd = parts[0].toLowerCase();

                switch (cmd) {
                    case "help" -> printHelp();

                    case "list" -> {
                        var entries = service.list(vault);
                        if (entries.isEmpty()) {
                            System.out.println("(no entries)");
                        } else {
                            for (VaultEntry e : entries) {
                                System.out.printf("%s | %s | %s%n", e.getId(), e.getSite(), e.getUsername());
                            }
                        }
                    }

                    case "find" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: find <text>");
                            break;
                        }

                        String q = line.substring(line.indexOf(' ') + 1).trim().toLowerCase();
                        if (q.isEmpty()) {
                            System.out.println("Usage: find <text>");
                            break;
                        }

                        var matches = vault.getEntries().stream()
                                .filter(e ->
                                        (e.getSite() != null && e.getSite().toLowerCase().contains(q)) ||
                                                (e.getUsername() != null && e.getUsername().toLowerCase().contains(q)) ||
                                                (e.getNotes() != null && e.getNotes().toLowerCase().contains(q))
                                )
                                .toList();

                        if (matches.isEmpty()) {
                            System.out.println("(no matches)");
                        } else {
                            for (var e : matches) {
                                System.out.printf("%s | %s | %s%n", e.getId(), e.getSite(), e.getUsername());
                            }
                        }
                    }

                    case "add" -> {
                        String site = prompt(sc, "Site: ");
                        String user = prompt(sc, "Username: ");
                        String pass;
                        while (true) {
                            pass = prompt(sc, "Password: ");
                            String err = PasswordPolicy.validate(pass);
                            if (err == null) break;
                            System.out.println("Weak password: " + err);
                            System.out.println("Tip: use 'gen 20 --no-ambiguous' to generate a strong one.");
                        }
                        String notes = promptOptional(sc, "Notes (optional): ");

                        VaultEntry created = service.add(vault, site, user, pass, notes);
                        dirty = true;
                        System.out.println("Added entry id=" + created.getId());
                    }

                    case "gen" -> {
                        int length = 16;
                        boolean includeSymbols = true;
                        boolean noAmbiguous = false;
                        boolean doCopy = false;

                        // Parse args
                        for (int i = 1; i < parts.length; i++) {
                            String p = parts[i].toLowerCase();
                            if (p.matches("\\d+")) {
                                length = Integer.parseInt(p);
                            } else if (p.equals("--no-symbols")) {
                                includeSymbols = false;
                            } else if (p.equals("--no-ambiguous")) {
                                noAmbiguous = true;
                            } else if (p.equals("--copy")) {
                                doCopy = true;
                            } else {
                                System.out.println("Unknown option: " + parts[i]);
                                System.out.println("Usage: gen [len] [--no-symbols] [--no-ambiguous] [--copy]");
                                break;
                            }
                        }

                        try {
                            String pw = generator.generate(length, includeSymbols, noAmbiguous);
                            System.out.println("Generated: " + pw);

                            if (doCopy) {
                                // reuse your existing clipboard method (auto-clear)
                                copyToClipboardWithAutoClear(pw, 15);
                            }

                            System.out.println("Tip: use this password in 'add' or 'update'.");
                        } catch (IllegalArgumentException e) {
                            System.out.println("Generator error: " + e.getMessage());
                        }
                    }

                    case "reveal" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: reveal <id>");
                            break;
                        }
                        String id = parts[1];

                        Optional<VaultEntry> opt = service.getById(vault, id);
                        if (opt.isEmpty()) {
                            System.out.println("Not found: " + id);
                            break;
                        }

                        if (!ensureUnlocked(vaultPath, sc)) break;

                        System.out.println("Password: " + opt.get().getPassword());
                    }

                    case "copy" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: copy <id>");
                            break;
                        }
                        String id = parts[1];

                        Optional<VaultEntry> opt = service.getById(vault, id);
                        if (opt.isEmpty()) {
                            System.out.println("Not found: " + id);
                            break;
                        }

                        if (!ensureUnlocked(vaultPath, sc)) break;

                        copyToClipboardWithAutoClear(opt.get().getPassword(), 15);
                    }

                    case "get" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: get <id>");
                            break;
                        }
                        String id = parts[1];
                        Optional<VaultEntry> opt = service.getById(vault, id);
                        if (opt.isEmpty()) {
                            System.out.println("Not found: " + id);
                        } else {
                            VaultEntry e = opt.get();
                            System.out.println("ID:       " + e.getId());
                            System.out.println("Site:     " + e.getSite());
                            System.out.println("Username: " + e.getUsername());
                            System.out.println("Password: " + "[hidden] (use reveal/copy)");                            System.out.println("Notes:    " + (e.getNotes() == null ? "" : e.getNotes()));
                            System.out.println("Created:  " + e.getCreatedAt());
                            System.out.println("Updated:  " + e.getUpdatedAt());
                        }
                    }

                    case "update" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: update <id>");
                            break;
                        }
                        String id = parts[1];
                        Optional<VaultEntry> opt = service.getById(vault, id);
                        if (opt.isEmpty()) {
                            System.out.println("Not found: " + id);
                            break;
                        }

                        VaultEntry current = opt.get();
                        System.out.println("Leave blank to keep existing values.");

                        String site = promptOptional(sc, "Site [" + current.getSite() + "]: ");
                        String user = promptOptional(sc, "Username [" + current.getUsername() + "]: ");
                        String pass = promptOptional(sc, "Password [hidden]: ");
                        String notes = promptOptional(sc, "Notes [" + safe(current.getNotes()) + "]: ");

                        // convert blanks -> null so service keeps old values
                        site = normalizeBlankToNull(site);
                        user = normalizeBlankToNull(user);
                        pass = normalizeBlankToNull(pass);
                        notes = normalizeBlankToNull(notes);

                        if (pass != null) {
                            String err = PasswordPolicy.validate(pass);
                            if (err != null) {
                                System.out.println("Weak password: " + err);
                                System.out.println("Update canceled. Use 'gen' and try again.");
                                break;
                            }
                        }

                        boolean ok = service.update(vault, id, site, user, pass, notes);
                        if (ok) {
                            dirty = true;
                            System.out.println("Updated: " + id);
                        } else {
                            System.out.println("Update failed: " + id);
                        }
                    }

                    case "delete" -> {
                        if (parts.length < 2) {
                            System.out.println("Usage: delete <id>");
                            break;
                        }
                        String id = parts[1];
                        System.out.print("Are you sure? (y/n): ");
                        String yn = sc.nextLine().trim().toLowerCase();
                        if (!yn.equals("y")) {
                            System.out.println("Canceled.");
                            break;
                        }
                        boolean removed = service.delete(vault, id);
                        if (removed) {
                            dirty = true;
                            System.out.println("Deleted: " + id);
                        } else {
                            System.out.println("Not found: " + id);
                        }
                    }

                    case "save" -> {
                        if (!ensureUnlocked(vaultPath, sc)) break;
                        repo.save(vaultPath, masterInMemory, vault);
                        dirty = false;
                        System.out.println("Saved.");
                    }

                    case "exit", "quit" -> {
                        if (dirty) {
                            System.out.print("You have unsaved changes. Save now? (y/n): ");
                            String yn = sc.nextLine().trim().toLowerCase();
                            touchActivity();

                            if (yn.equals("y")) {
                                if (!ensureUnlocked(vaultPath, sc)) {
                                    System.out.println("Could not unlock; exiting without saving.");
                                } else {
                                    repo.save(vaultPath, masterInMemory, vault);
                                    System.out.println("Saved.");
                                }
                            }
                        }

                        if (autoLockTask != null) autoLockTask.cancel(true);
                        scheduler.shutdownNow();

                        lockNow(); // wipes masterInMemory
                        System.out.println("Bye.");
                        return;
                    }

                    case "unlock" -> unlock(vaultPath, sc);

                    case "lock" -> {
                        lockNow();
                    }

                    case "status" -> {
                        boolean unlocked = masterInMemory != null;
                        long idleSec = (System.currentTimeMillis() - lastActivityMs.get()) / 1000L;
                        System.out.println("State: " + (unlocked ? "UNLOCKED" : "LOCKED"));
                        System.out.println("Idle: " + idleSec + "s / " + AUTO_LOCK_SECONDS + "s");
                    }

                    default -> System.out.println("Unknown command. Type 'help'.");
                }
            }
        }
    }

    private static void printHelp() {
        System.out.println("""
Commands:
  help
  list
  add
  find <text>
  reveal <id>
  copy <id>
  get <id>
  update <id>
  delete <id>
  gen
  save
  status
  lock
  unlock
  exit
""");
    }

    private static String prompt(Scanner sc, String label) {
        while (true) {
            System.out.print(label);
            String v = sc.nextLine().trim();
            if (!v.isEmpty()) return v;
            System.out.println("Required.");
        }
    }

    private static char[] promptPassword(Scanner sc, String label) {
        // Simple approach (Scanner). Upgrade later to Console.readPassword() if available.
        System.out.print(label);
        return sc.nextLine().toCharArray();
    }

    private static String promptOptional(Scanner sc, String label) {
        System.out.print(label);
        return sc.nextLine();
    }

    private static String normalizeBlankToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private boolean verifyMaster(Path vaultPath, Scanner sc) {
        char[] attempt = promptPassword(sc, "Re-enter master password: ");
        try {
            // If this succeeds, password is correct and file wasn't tampered with.
            repo.load(vaultPath, attempt);
            return true;
        } catch (Exception e) {
            System.out.println("Verification failed (wrong password or vault corrupted).");
            return false;
        } finally {
            CryptoService.wipe(attempt);
        }
    }

    private void touchActivity() {
        lastActivityMs.set(System.currentTimeMillis());
    }

    private void lockNow() {
        if (masterInMemory != null) {
            CryptoService.wipe(masterInMemory);
            masterInMemory = null;
            System.out.println("\n[locked] Auto-lock engaged. Use 'unlock' to continue sensitive actions.");
            System.out.print("cmd> ");
        }
    }

    private void startAutoLockMonitor() {
        // Run every 1 second; lock if idle too long
        autoLockTask = scheduler.scheduleAtFixedRate(() -> {
            try {
                long idleMs = System.currentTimeMillis() - lastActivityMs.get();
                if (masterInMemory != null && idleMs >= AUTO_LOCK_SECONDS * 1000L) {
                    lockNow();
                }
            } catch (Exception ignored) {}
        }, 1, 1, TimeUnit.SECONDS);
    }

    private boolean unlock(Path vaultPath, Scanner sc) {
        applyUnlockBackoff();

        char[] attempt = promptPassword(sc, "Master password: ");
        try {
            repo.load(vaultPath, attempt);

            // success: reset counters, store master
            failedUnlocks.set(0);

            if (masterInMemory != null) CryptoService.wipe(masterInMemory);
            masterInMemory = attempt;

            touchActivity();
            System.out.println("[unlocked]");
            return true;

        } catch (Exception e) {
            failedUnlocks.incrementAndGet();
            System.out.println("Unlock failed (wrong password or vault corrupted).");
            CryptoService.wipe(attempt);
            return false;
        }
    }
    private boolean ensureUnlocked(Path vaultPath, Scanner sc) {
        if (masterInMemory != null) return true;
        System.out.println("Vault is locked. Use 'unlock' or run the command again after unlocking.");
        return unlock(vaultPath, sc);
    }

    private void copyToClipboardWithAutoClear(String secret, int seconds) {
        try {
            var clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(secret), null);
            System.out.println("Copied to clipboard. Will clear in " + seconds + " seconds.");

            scheduler.schedule(() -> {
                try {
                    clipboard.setContents(new StringSelection(""), null);
                    // (Optional) print message so user knows it cleared
                    System.out.println("\n(clipboard cleared)");
                    System.out.print("cmd> ");
                } catch (Exception ignored) {}
            }, seconds, TimeUnit.SECONDS);

        } catch (Exception e) {
            // Common on headless environments / some terminals
            System.out.println("Clipboard not available here. Use 'reveal <id>' instead.");
        }
    }

    private static class DaemonThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("clipboard-clear");
            return t;
        }
    }

    private void applyUnlockBackoff() {
        int fails = failedUnlocks.get();
        if (fails >= MAX_FAILS_BEFORE_DELAY) {
            int blocks = (fails - MAX_FAILS_BEFORE_DELAY) / MAX_FAILS_BEFORE_DELAY; // 0,1,2...
            int delay = BASE_DELAY_SECONDS * (1 << blocks); // 30, 60, 120...
            if (delay > 300) delay = 300; // cap at 5 minutes

            System.out.println("Too many failed attempts. Waiting " + delay + " seconds...");
            try {
                Thread.sleep(delay * 1000L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }





}