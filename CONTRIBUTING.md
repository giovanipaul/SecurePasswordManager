# Contributing

Contributions and security-minded reviews are welcome.

## Development

Requirements:

- JDK 17 or newer
- Git

Run the complete local quality gate:

```bash
./mvnw spotless:apply
./mvnw clean verify
```

The verification build runs unit and integration-style tests, enforces the
coverage floor, performs static analysis, checks formatting, and packages the
runnable JAR.

## Pull Requests

Keep changes focused and include tests for changed behavior. In the pull request
description, explain:

- The user-visible behavior
- Security or compatibility implications
- Tests performed
- Any vault-format migration requirements

Never commit a real vault, master password, credential, generated coverage
report, IDE settings, or build output.

