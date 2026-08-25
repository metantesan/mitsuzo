# Mitsuzo

Encrypted pastebin with end-to-end encryption.

## Features

- **Client-side encryption** — ChaCha20Poly1305 + Argon2id, all in your browser
- **Zero-knowledge password validation** — server never sees your password or plaintext
- **Chunked encryption** — supports pastes up to 1 GB, 64 KB chunks with unique nonces
- **Self-destructing pastes** — TTL + try-count limits, auto-deleted on expiry
- **File upload with preview** — images previewed inline, files downloadable
- **CLI client** — `create` and `get` commands
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
```

## Architecture

```
crates/
├── backend/     Axum HTTP server, sled metadata DB, filesystem storage
├── frontend/    Dioxus WASM app
├── cli/         Rust CLI client
├── types/       Shared types + bitcode serialization
└── utils/       Argon2id, ChaCha20Poly1305, HMAC-SHA256
```

## Security

- Argon2id (19MB memory, 2 iterations, 1 parallel) → 64 bytes split into encryption + validation keys
- ChaCha20Poly1305 authenticated encryption
- HMAC-SHA256 for password validation (encryption key never leaves your device)
- Constant-time comparison against timing attacks
- No plaintext on server — even full compromise cannot expose data

## License

BSD-3-Clause
