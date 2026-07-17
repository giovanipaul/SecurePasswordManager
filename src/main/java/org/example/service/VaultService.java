package org.example.service;


import org.example.model.Vault;
import org.example.model.VaultEntry;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public class VaultService {

    public List<VaultEntry> list(Vault vault) {
        return vault.getEntries().stream()
                .sorted(Comparator.comparing(VaultEntry::getSite, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    public Optional<VaultEntry> getById(Vault vault, String id) {
        if (id == null || id.isBlank()) return Optional.empty();
        return vault.getEntries().stream()
                .filter(e -> id.equals(e.getId()))
                .findFirst();
    }

    public List<VaultEntry> search(Vault vault, String query) {
        String normalized = requireNonBlank(query, "Search text").toLowerCase(Locale.ROOT);
        return list(vault).stream()
                .filter(entry -> contains(entry.getSite(), normalized)
                        || contains(entry.getUsername(), normalized)
                        || contains(entry.getNotes(), normalized))
                .toList();
    }

    public VaultEntry add(Vault vault, String site, String username, String password, String notes) {
        String cleanSite = requireNonBlank(site, "Service name");
        String cleanUsername = requireNonBlank(username, "Username");
        String cleanPassword = requireNonBlank(password, "Password");
        ensureUnique(vault, cleanSite, cleanUsername, null);

        VaultEntry e = new VaultEntry(cleanSite, cleanUsername, cleanPassword, normalizeOptional(notes));
        vault.getEntries().add(e);
        return e;
    }

    public boolean delete(Vault vault, String id) {
        return vault.getEntries().removeIf(e -> e.getId().equals(id));
    }

    public boolean update(Vault vault, String id, String site, String username, String password, String notes) {
        Optional<VaultEntry> opt = getById(vault, id);
        if (opt.isEmpty()) return false;

        VaultEntry e = opt.get();
        String nextSite = site == null ? e.getSite() : requireNonBlank(site, "Service name");
        String nextUsername = username == null ? e.getUsername() : requireNonBlank(username, "Username");
        String nextPassword = password == null ? e.getPassword() : requireNonBlank(password, "Password");
        ensureUnique(vault, nextSite, nextUsername, id);

        if (site != null) e.setSite(nextSite);
        if (username != null) e.setUsername(nextUsername);
        if (password != null) e.setPassword(nextPassword);
        if (notes != null) e.setNotes(normalizeOptional(notes));
        return true;
    }

    public int clear(Vault vault) {
        int removed = vault.getEntries().size();
        vault.getEntries().clear();
        return removed;
    }

    private static void ensureUnique(Vault vault, String site, String username, String excludedId) {
        boolean duplicate = vault.getEntries().stream()
                .filter(entry -> excludedId == null || !excludedId.equals(entry.getId()))
                .anyMatch(entry -> equalsIgnoreCase(entry.getSite(), site)
                        && equalsIgnoreCase(entry.getUsername(), username));
        if (duplicate) {
            throw new IllegalArgumentException(
                    "An entry already exists for this service and username.");
        }
    }

    private static boolean contains(String value, String normalizedQuery) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(normalizedQuery);
    }

    private static boolean equalsIgnoreCase(String left, String right) {
        return left != null && right != null && left.equalsIgnoreCase(right);
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " cannot be empty.");
        }
        return value.trim();
    }

    private static String normalizeOptional(String value) {
        if (value == null) return "";
        return value.trim();
    }
}
