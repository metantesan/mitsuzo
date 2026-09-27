# Contributing to Mitsuzo

Thanks for taking an interest in Mitsuzo. Contributions are welcome, especially
security reviews, documentation improvements, interoperability work, and tests.

## Before opening a pull request

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

For frontend changes, also build the web package with the version of Dioxus
listed in the repository configuration.

## Pull requests

- Explain the user problem and the intended behavior.
- Keep changes focused and include tests for security-sensitive logic.
- Update the README or docs when behavior or deployment changes.
- Do not include real secrets, private keys, or user data in examples.

Please report security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), rather than opening a public issue.
