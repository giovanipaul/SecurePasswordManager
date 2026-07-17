package org.example.service;


import org.example.model.Vault;
import org.example.model.VaultEntry;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public class VaultService {

    public List<VaultEntry> list(Vault vault) {
        return vault.getEntries().stream()
                .sorted(Comparator.comparing(VaultEntry::getSite, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    public Optional<VaultEntry> getById(Vault vault, String id) {
        return vault.getEntries().stream()
                .filter(e -> e.getId().equals(id))
                .findFirst();
    }

    public VaultEntry add(Vault vault, String site, String username, String password, String notes) {
        VaultEntry e = new VaultEntry(site, username, password, notes);
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
        if (site != null) e.setSite(site);
        if (username != null) e.setUsername(username);
        if (password != null) e.setPassword(password);
        if (notes != null) e.setNotes(notes);
        return true;
    }
}