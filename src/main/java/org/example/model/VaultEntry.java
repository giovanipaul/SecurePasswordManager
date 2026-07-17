package org.example.model;

import java.time.Instant;
import java.util.UUID;

public class VaultEntry {
    private String id;
    private String site;
    private String username;
    private String password;
    private String notes;
    private Instant createdAt;
    private Instant updatedAt;

    public VaultEntry() { }

    public VaultEntry(String site, String username, String password, String notes) {
        this.id = UUID.randomUUID().toString();
        this.site = site;
        this.username = username;
        this.password = password;
        this.notes = notes;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    // getters/setters
    public String getId() { return id; }
    public String getSite() { return site; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getNotes() { return notes; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setSite(String site) { this.site = site; touch(); }
    public void setUsername(String username) { this.username = username; touch(); }
    public void setPassword(String password) { this.password = password; touch(); }
    public void setNotes(String notes) { this.notes = notes; touch(); }

    private void touch() { this.updatedAt = Instant.now(); }
}