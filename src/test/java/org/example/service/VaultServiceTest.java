package org.example.service;

import org.example.model.Vault;
import org.example.model.VaultEntry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VaultServiceTest {
    private final VaultService service = new VaultService();

    @Test
    void supportsCrudAndCaseInsensitiveSearch() {
        Vault vault = new Vault();
        VaultEntry entry = service.add(vault, "Example", "giovani", "ValidPass1!", "personal");

        assertEquals(1, service.list(vault).size());
        assertEquals(entry, service.search(vault, "EXAMP").get(0));
        assertTrue(service.update(vault, entry.getId(), "Example App", null, null, "updated"));
        assertEquals("Example App", service.getById(vault, entry.getId()).orElseThrow().getSite());
        assertTrue(service.delete(vault, entry.getId()));
        assertTrue(service.list(vault).isEmpty());
    }

    @Test
    void rejectsBlankRequiredFields() {
        Vault vault = new Vault();
        assertEquals("Service name cannot be empty.",
                assertThrows(IllegalArgumentException.class,
                        () -> service.add(vault, " ", "user", "ValidPass1!", "")).getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> service.add(vault, "Example", " ", "ValidPass1!", ""));
        assertThrows(IllegalArgumentException.class,
                () -> service.add(vault, "Example", "user", " ", ""));
    }

    @Test
    void rejectsDuplicateServiceAndUsernameIgnoringCase() {
        Vault vault = new Vault();
        service.add(vault, "Example", "User", "ValidPass1!", "");

        assertThrows(IllegalArgumentException.class,
                () -> service.add(vault, "example", "user", "AnotherPass2!", ""));
    }

    @Test
    void clearReturnsNumberOfRemovedEntries() {
        Vault vault = new Vault();
        service.add(vault, "One", "a", "ValidPass1!", "");
        service.add(vault, "Two", "b", "ValidPass2!", "");
        assertEquals(2, service.clear(vault));
        assertTrue(vault.getEntries().isEmpty());
    }
}
