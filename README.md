# Mitsuzo

Encrypted pastebin with end-to-end encryption.

## Features

- **Client-side encryption** — ChaCha20Poly1305 + Argon2id, all in your browser
- **Envelope encryption** — data is encrypted with a random per-paste content key, wrapped with the password-derived key
- **Changeable password** — re-wraps only the content key; paste data is never re-encrypted or re-uploaded (web UI and `cli passwd`)
- **Zero-knowledge password validation** — server never sees your password or plaintext
- **Chunked encryption** — supports pastes up to 1 GB, 64 KB chunks with unique nonces
- **Self-destructing pastes** — TTL + try-count limits, auto-deleted on expiry
- **Burn after reading** — cryptographic receipt proves full decryption before deletion
- **File upload with preview** — images previewed inline, files downloadable
- **CLI client** — `create`, `get`, and `passwd` commands
- **i18n** — English and Persian
- **Dark theme**

## Quick Start

```bash
docker run -p 3030:3030 ghcr.io/metantesan/mitsuzo:latest
```

Open http://localhost:3030.

### Live demo mode

The server can be run as a restricted live demo with a short TTL and a small upload limit.
It is configured through environment variables:

| Variable | Default (normal) | Demo default | Description |
| --- | --- | --- | --- |
| `MITSUZO_DEMO_MODE` | unset | `1` | Enable demo mode. Accepts `1`, `true`, `yes`, `on`. |
| `MITSUZO_MAX_TTL_SECONDS` | `43200` (12 h) | `60` (1 min) | Maximum paste TTL in seconds. |
| `MITSUZO_MAX_FILE_SIZE_BYTES` | `1073741824` (1 GB) | `5242880` (5 MB) | Maximum paste/file size in bytes. |

When demo mode is on, pastes expire after at most 1 minute, cannot exceed 5 MB, and the
frontend shows a "Live demo" badge together with a notice about the limits:

```bash
docker run -p 3030:3030 -e MITSUZO_DEMO_MODE=1 ghcr.io/metantesan/mitsuzo:latest
```

### Build from source

```bash
cd crates/frontend && dx build --release && cd ../..
cargo build --release -p backend -p cli
./target/release/backend
```

### CLI

```bash
echo "secret message" | cli create
cli create --file document.pdf
cli get 123456
cli get 123456 --output decrypted.pdf
cli passwd 123456
```

## Architecture

```
crates/
├── backend/     Axum HTTP server, sled metadata DB, filesystem storage
├── frontend/    Dioxus WASM app
├── cli/         Rust CLI client
├── types/       Shared types + bitcode serialization
└── utils/       Argon2id, HKDF-SHA256, ChaCha20Poly1305, HMAC-SHA256
```

## Security

- **Envelope encryption**: a random 32-byte content key (CEK) encrypts the data — the password never directly touches your content
- Argon2id (19 MB memory, 2 iterations, 1 parallel) → 32-byte master key → HKDF-SHA256 expands into a key-encryption key (KEK) + validation key
- The CEK is wrapped with ChaCha20Poly1305 under the KEK and stored server-side; changing the password unwraps and re-wraps only the CEK — ciphertext is untouched
- Legacy pastes (pre-envelope) still decrypt via the old direct derived-key path
- ChaCha20Poly1305 authenticated encryption, 64 KB chunks with unique nonces
- HMAC-SHA256 for password validation (encryption key never leaves your device)
- Constant-time comparison against timing attacks
- No plaintext on server — even full compromise cannot expose data

## License

BSD-3-Clause
