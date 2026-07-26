package io.github.giovanipaul.securepasswordmanager.model;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.util.ArrayList;
import java.util.List;

public class Vault {
	private List<VaultEntry> entries = new ArrayList<>();

	@SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "Vault is the mutable aggregate root; VaultService intentionally edits this collection.")
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
