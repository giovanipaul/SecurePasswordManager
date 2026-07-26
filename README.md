# Secure Password Manager

[![CI](https://github.com/giovanipaul/SecurePasswordManager/actions/workflows/ci.yml/badge.svg)](https://github.com/giovanipaul/SecurePasswordManager/actions/workflows/ci.yml)
![Java 17+](https://img.shields.io/badge/Java-17%2B-ED8B00?logo=openjdk&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An offline Java password manager demonstrating authenticated encryption,
crash-safe persistence, session lifecycle management, automated testing, and
cross-platform delivery.

The application stores credentials in a locally encrypted JSON vault. It is
intentionally small and reviewable: Java 17, Maven, Jackson, PBKDF2, and AES-GCM
without a UI framework or database server.

> This project is educational software, not a replacement for an independently audited commercial password manager.

## Why This Project

This repository focuses on the engineering around sensitive local data:
versioned encrypted storage, authenticated metadata, backwards compatibility,
atomic file replacement, explicit threat modeling, and failure-path tests. See
[ARCHITECTURE.md](ARCHITECTURE.md) for design decisions and [SECURITY.md](SECURITY.md)
for the threat model.

## Features

- Numbered main menu with text-command shortcuts
- Create, list, search, view, update, and delete credentials
- Select credentials by number instead of copying internal IDs
- Passwords masked unless the user explicitly reveals one
- Master-password re-verification before revealing or copying a saved password
- Configurable strong-password generator
- Automatic encrypted save after every successful change
- Manual save, lock/unlock, status, help, and clear-vault actions
- Atomic master-password rotation
- Five-minute inactivity auto-lock
- Clipboard copy with conditional automatic clearing (15 seconds by default)
- Duplicate and blank-field validation
- Friendly handling of invalid commands, damaged files, wrong passwords, and unavailable clipboards
- Atomic vault-file replacement to protect the previous saved file when a write fails

## Security Design

The application stores one JSON envelope containing Base64-encoded encryption metadata and ciphertext. Service names, usernames, passwords, and notes are encrypted together; they are not written as plaintext fields.

- **Versioned envelope:** v2 stores explicit KDF, iteration, key-length, and cipher parameters; legacy v1 vaults remain readable
- **Key derivation:** PBKDF2-HMAC-SHA-256 with a random 16-byte salt, 210,000 iterations, and a 256-bit derived key
- **Encryption:** AES-256-GCM with a random 12-byte IV and 128-bit authentication tag
- **Integrity:** AES-GCM rejects a wrong master password, modified ciphertext, or modified v2 encryption metadata
- **Fresh encryption metadata:** every save generates a new salt and IV
- **Session handling:** the in-memory master-password character array is cleared on lock and exit where reasonably possible
- **Sensitive actions:** saved passwords remain masked and require master-password verification before reveal or copy
- **Safe saving:** encrypted output is written to a temporary file and then moved into place
- **Defensive parsing:** vault and ciphertext sizes are bounded before expensive parsing or decryption
- **Local data protection:** `vault.json` and temporary vault files are excluded by `.gitignore`

No encryption keys or passwords are hard-coded in the source.

## Requirements

- Java Development Kit (JDK) 17 or newer
- macOS, Linux, or Windows terminal

The included Maven wrapper downloads the correct Maven version automatically.

## Build and Run

### macOS or Linux

```bash
./mvnw clean test
./mvnw exec:java
```

### Windows

```powershell
mvnw.cmd clean test
mvnw.cmd exec:java
```

Build the self-contained executable JAR:

```bash
./mvnw clean verify
java -jar target/secure-password-manager-1.0-SNAPSHOT-all.jar
```

`verify` runs tests, coverage enforcement, SpotBugs, formatting checks, and
packaging. GitHub Actions repeats the complete gate on Linux, macOS, and Windows
with Java 17 and 21. CI artifacts include the runnable JAR and coverage report.

By default, the encrypted vault is saved as `vault.json` in the current directory. To use a different location:

```bash
./mvnw exec:java -Dexec.args="/path/to/my-vault.json"
```

On first run, create and confirm a master password. It must contain at least 12 characters, including uppercase, lowercase, numeric, and symbol characters.

## Main Commands

| Menu | Command | Purpose |
|---:|---|---|
| 1 | `list` | List services and usernames with masked passwords |
| 2 | `add` | Add a credential with a typed or generated password |
| 3 | `view` | View metadata, reveal a password, or copy it |
| 4 | `update` | Update selected fields while retaining blank fields |
| 5 | `delete` | Delete one credential after confirmation |
| 6 | `search` | Search service, username, or notes |
| 7 | `generate` | Generate a password and reveal or copy it once |
| 8 | `save` | Manually encrypt and save the vault |
| 9 | `clear` | Delete every credential after typing `CLEAR` |
| 10 | `lock` / `unlock` | Close or reopen the sensitive session |
| 11 | `status` | Display lock, save, timeout, clipboard, and path details |
| 12 | `help` | Explain every feature and command |
| 13 | `password` | Verify the current master password and atomically re-encrypt with a new one |
| 0 | `exit` | Save if needed, lock, and close |

## Sample Usage

```text
============================================================
                 SECURE PASSWORD MANAGER
============================================================
Encrypted local credential storage for personal use.
Passwords stay masked unless you explicitly reveal them.

[OK] Vault unlocked. 2 saved credential(s) loaded.

-------------------------- MAIN MENU -------------------------
  1. List credentials        7. Generate password
  2. Add credential          8. Save vault
  3. View / reveal / copy    9. Clear vault
  4. Update credential      10. Lock or unlock
  5. Delete credential      11. Vault status
  6. Search credentials     12. Help
  0. Save and exit
--------------------------------------------------------------
Choose an option: 1

--- Saved Credentials ---
No.  Service                    Username                         Password
---- -------------------------- -------------------------------- --------
1    Example                    user@example.com                 ********
2    School Portal              student                         ********
```

## Configuring Clipboard Clearing

The clipboard clears after 15 seconds by default. Set a value from 1 to 300 seconds with a JVM system property:

```bash
./mvnw exec:java -Dpasswordmanager.clipboardClearSeconds=30
```

If the operating system or terminal does not allow clipboard access, the application shows a readable message and leaves the vault unchanged.

## Project Structure

```text
src/
├── main/java/io/github/giovanipaul/securepasswordmanager/
│   ├── Main.java                    Application wiring and vault-path selection
│   ├── crypto/CryptoService.java    PBKDF2, AES-GCM, random salt/IV, memory wiping
│   ├── model/                       Vault and credential data objects
│   ├── service/
│   │   ├── VaultService.java        Validation, search, and CRUD operations
│   │   ├── VaultSession.java        Lock state and inactivity timeout
│   │   ├── PasswordGenerator.java   Secure password generation
│   │   └── PasswordPolicy.java      Password-strength validation
│   ├── storage/                     Encrypted JSON persistence and file envelope
│   └── ui/
│       ├── ConsoleUI.java           Menu workflows, prompts, and readable messages
│       └── ClipboardService.java    Copy and timed clipboard clearing
└── test/java/io/github/giovanipaul/securepasswordmanager/
                                       JUnit tests organized by package
```

The separation is deliberately simple: the UI collects choices, services enforce application rules, the repository owns storage, and the crypto class owns cryptographic operations.

## Tests

Run all tests:

```bash
./mvnw test
```

The 24-test JUnit suite covers:

- CRUD, search, duplicate handling, blank fields, and clear-vault behavior
- Password policy and generator constraints
- AES-GCM encryption/decryption and wrong-key rejection
- Authenticated metadata and legacy v1 compatibility
- Encrypted persistence, oversized/corrupted input, atomic temporary-file cleanup, and overwrite protection
- Master-password rotation and rejection of the previous password
- Auto-lock expiration and activity refresh
- First-run vault creation, numbered menu persistence, and invalid-command terminal guidance

## Current Limitations

- The vault is decrypted into Java objects while unlocked, so credential strings may remain in JVM memory until garbage collected.
- Java `String` objects cannot be reliably wiped; character and byte arrays are cleared only where practical.
- Password input is masked when launched from a supported system console. Some IDE consoles do not provide secure password input and may display typed characters.
- Clipboard clearing is best-effort. It only clears when the clipboard still contains the copied password, but another application or clipboard-history service may retain it.
- The application does not provide account recovery. Losing the master password means losing access to the vault.
- The v2 envelope supports future parameter migration, but the current implementation only supports PBKDF2-HMAC-SHA-256.
- The project has not received an independent security audit.

## Future Improvements

- Add optional encrypted backup and restore commands
- Add password-strength feedback without weakening the existing policy
- Add an Argon2id KDF option and migrate v2 PBKDF2 vaults after successful unlock
- Expand terminal integration tests for update, delete, reveal, clipboard, and failed-save flows

## Project Standards

- CI: Java 17 and 21 across Linux, macOS, and Windows
- Coverage: JaCoCo report with a non-regression floor
- Static analysis: SpotBugs fails the build on findings
- Formatting: Spotless verifies Java and Maven files
- Dependencies: Dependabot monitors Maven and GitHub Actions
- Releases: the build produces a reproducible, self-contained runnable JAR

Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md), and notable
changes are tracked in [CHANGELOG.md](CHANGELOG.md).
