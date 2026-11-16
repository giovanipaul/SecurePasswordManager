# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and releases use semantic versioning.

## [Unreleased]

### Added

- Check passwords against the HaveIBeenPwned breach database using k-anonymity: only the first 5 characters of the password's SHA-1 hash are sent, and the password itself never leaves the machine

## [1.1.0] - 2026-11-16

### Security

- Increased PBKDF2 iterations for new vault saves from 210,000 to 600,000 while preserving legacy vault compatibility
- Offer an optional key derivation upgrade after successfully unlocking an older vault
- Create vault temporary files with owner-only permissions on POSIX file systems

### Changed

- Updated Maven dependencies, plugins, and GitHub Actions
- Added a terminal demo and documented security design decisions

## [1.0.0] - 2026-07-25

### Added

- Cross-platform continuous integration
- Runnable JAR packaging
- Coverage, formatting, static-analysis, and build-environment quality gates
- Architecture, contribution, and security documentation
- Automated dependency update configuration
- Version 2 vault envelopes with authenticated algorithm metadata
- Backwards-compatible version 1 vault loading
- Atomic master-password rotation
- Defensive vault and ciphertext size limits
- Encrypted local credential CRUD and search
- PBKDF2-HMAC-SHA-256 key derivation and AES-256-GCM encryption
- Atomic vault persistence
- Configurable password generation
- Inactivity auto-lock and master-password re-verification
- Timed clipboard clearing
- JUnit test suite

### Changed

- Clipboard clearing now preserves content copied after the password
- All text input uses an explicit UTF-8 charset

### Security

- Added authenticated encryption metadata and adversarial tampering tests
- Added SpotBugs enforcement with zero outstanding findings
