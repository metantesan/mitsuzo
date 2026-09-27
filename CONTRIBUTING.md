# Contributing to Mitsuzo

Contributions are welcome, especially security reviews, documentation,
interoperability work, and tests.

## Before opening a pull request

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

For frontend changes, also build the web package with the Dioxus version used
by the repository configuration.

## Pull requests

- Explain the user problem and intended behavior.
- Keep changes focused and include tests for security-sensitive logic.
- Update the README or in-app docs when behavior or deployment changes.
- Never include real secrets, private keys, or user data in examples.

Please report vulnerabilities privately according to [SECURITY.md](SECURITY.md)
instead of opening a public issue.
