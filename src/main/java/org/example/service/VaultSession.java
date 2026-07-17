package org.example.service;

import org.example.crypto.CryptoService;

import java.time.Duration;
import java.util.Arrays;
import java.util.function.LongSupplier;

/** Keeps the master password only for the active unlocked session. */
public class VaultSession implements AutoCloseable {
    private final long timeoutMillis;
    private final LongSupplier currentTimeMillis;
    private char[] masterPassword;
    private long lastActivityMillis;

    public VaultSession(Duration timeout) {
        this(timeout, System::currentTimeMillis);
    }

    VaultSession(Duration timeout, LongSupplier currentTimeMillis) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("Auto-lock timeout must be positive.");
        }
        this.timeoutMillis = timeout.toMillis();
        this.currentTimeMillis = currentTimeMillis;
        this.lastActivityMillis = currentTimeMillis.getAsLong();
    }

    public synchronized void unlock(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Master password cannot be empty.");
        }
        lock();
        masterPassword = Arrays.copyOf(password, password.length);
        touch();
    }

    public synchronized boolean isUnlocked() {
        lockIfExpired();
        return masterPassword != null;
    }

    public synchronized char[] copyMasterPassword() {
        lockIfExpired();
        if (masterPassword == null) {
            throw new IllegalStateException("Vault is locked.");
        }
        touch();
        return Arrays.copyOf(masterPassword, masterPassword.length);
    }

    public synchronized void touch() {
        lastActivityMillis = currentTimeMillis.getAsLong();
    }

    public synchronized boolean lockIfExpired() {
        if (masterPassword != null
                && currentTimeMillis.getAsLong() - lastActivityMillis >= timeoutMillis) {
            lock();
            return true;
        }
        return false;
    }

    public synchronized void lock() {
        CryptoService.wipe(masterPassword);
        masterPassword = null;
    }

    public long timeoutSeconds() {
        return timeoutMillis / 1_000L;
    }

    @Override
    public void close() {
        lock();
    }
}
