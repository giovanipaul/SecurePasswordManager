package org.example.service;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class VaultSessionTest {
    @Test
    void autoLocksAfterConfiguredInactivity() {
        AtomicLong now = new AtomicLong(1_000L);
        VaultSession session = new VaultSession(Duration.ofSeconds(5), now::get);
        session.unlock("StrongMaster1!".toCharArray());
        assertTrue(session.isUnlocked());

        now.addAndGet(4_999L);
        assertTrue(session.isUnlocked());
        now.addAndGet(5_000L);
        assertFalse(session.isUnlocked());
        assertThrows(IllegalStateException.class, session::copyMasterPassword);
    }

    @Test
    void activityExtendsSession() {
        AtomicLong now = new AtomicLong(0L);
        VaultSession session = new VaultSession(Duration.ofSeconds(5), now::get);
        session.unlock("StrongMaster1!".toCharArray());
        now.set(4_000L);
        session.touch();
        now.set(8_000L);
        assertTrue(session.isUnlocked());
    }
}
