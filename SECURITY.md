# Security Policy

## Scope

Secure Password Manager is an educational portfolio project. It demonstrates
authenticated encryption and defensive local persistence, but it has not been
independently audited and should not replace an audited password manager.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability. Use the
[repository's private security advisory page](https://github.com/giovanipaul/SecurePasswordManager/security/advisories/new)
and include:

- The affected version or commit
- Reproduction steps or a proof of concept
- The likely impact
- Any suggested mitigation

Reports will be acknowledged as soon as practical. A fix and coordinated
disclosure timeline will be agreed upon before details are published.

## Threat Model

The application is designed to protect vault contents when the encrypted vault
file is copied, lost, or modified by an attacker who does not know the master
password. AES-GCM provides confidentiality and tamper detection, while the
password-based key derivation function raises the cost of offline guessing.

The application does not claim to protect against:

- Malware, keyloggers, screen capture, or a compromised operating system
- An attacker who knows or observes the master password
- Secrets retained by terminal scrollback or clipboard-history software
- Weak master passwords subjected to offline guessing
- Secrets remaining in JVM-managed `String` objects until garbage collection
- Denial of service through deletion or replacement of the vault file

## Security Invariants

- Vault entry fields are encrypted together, never stored as plaintext JSON.
- Each save uses fresh random salt and IV values.
- Authentication failures never replace the existing vault.
- Writes use a temporary sibling file followed by an atomic move when supported.
- Master-password arrays and intermediate byte arrays are wiped where Java
  permits a meaningful best-effort wipe.
- No recovery mechanism or hidden key exists.
