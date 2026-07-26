# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and releases use semantic versioning.

## [Unreleased]

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

### Changed

- Clipboard clearing now preserves content copied after the password
- All text input uses an explicit UTF-8 charset

### Security

- Added authenticated encryption metadata and adversarial tampering tests
- Added SpotBugs enforcement with zero outstanding findings

## [1.0.0] - 2026-07-25

### Added

- Encrypted local credential CRUD and search
- PBKDF2-HMAC-SHA-256 key derivation and AES-256-GCM encryption
- Atomic vault persistence
- Configurable password generation
- Inactivity auto-lock and master-password re-verification
- Timed clipboard clearing
- JUnit test suite
