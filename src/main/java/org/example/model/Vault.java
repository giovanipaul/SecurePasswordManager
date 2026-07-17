package org.example.model;

import java.util.ArrayList;
import java.util.List;

public class Vault {
    private List<VaultEntry> entries = new ArrayList<>();

    public List<VaultEntry> getEntries() {
        if (entries == null) {
            entries = new ArrayList<>();
        }
        return entries;
    }

    public void setEntries(List<VaultEntry> entries) {
        this.entries = entries == null ? new ArrayList<>() : new ArrayList<>(entries);
    }
}
