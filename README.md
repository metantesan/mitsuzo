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
- **User accounts** — a BIP39 seed phrase deterministically derives an X25519 identity; the private key is password-encrypted and kept only on your device
- **Paste-to-user** — encrypt pastes to an account's public key via X25519 ECDH; the sender can reopen them with their ephemeral key
- **Account inbox & profiles** — per-account paste lists and public profile pages, protected by single-use X25519 challenges
- **File upload with preview** — images previewed inline, files downloadable
- **CLI client** — `create`, `get`, `passwd`, and `account` commands
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
cli create --to 0x29fb…        # encrypt to a user account
cli get 123456
cli get 123456 --output decrypted.pdf
cli passwd 123456
cli account register --name alice   # generate a seed phrase + register
cli account import --name alice     # restore an account from a seed phrase
cli account login
```

## Architecture

```
crates/
├── backend/     Axum HTTP server, sled metadata DB, filesystem storage, in-memory challenge store
├── frontend/    Dioxus WASM app
├── cli/         Rust CLI client (create, get, passwd, account)
├── types/       Shared types + bitcode serialization
└── utils/       Argon2id, HKDF-SHA256, ChaCha20Poly1305, HMAC-SHA256, X25519/ECDH
```

## Security

- **Envelope encryption**: a random 32-byte content key (CEK) encrypts the data — the password never directly touches your content
- Argon2id (19 MB memory, 2 iterations, 1 parallel) → 32-byte master key → HKDF-SHA256 expands into a key-encryption key (KEK) + validation key
- The CEK is wrapped with ChaCha20Poly1305 under the KEK and stored server-side; changing the password unwraps and re-wraps only the CEK — ciphertext is untouched
- Paste metadata is password-gated: only the Argon2id salt is public (it is required to derive the validation key); nonce, file info, wrapped key, and try count are delivered in the authenticated `/data` frame after the password check
- Failed attempts answer 401 with the remaining try count, and try-count enforcement is purely server-side
- Legacy pastes (pre-envelope) still decrypt via the old direct derived-key path
- **Zero-knowledge accounts** — an account is an X25519 identity derived from a BIP39 seed phrase; the server stores only the public key and a display name, and the private key never leaves your device
- **Recipient mode** — content keys are sealed to a recipient's public key with `HKDF-SHA256(X25519 ECDH)`; by symmetry both the recipient (via their account key) and the sender (via the one-shot ephemeral key) can open the envelope
- **Challenge-based auth** — login, inbox, name changes, and recipient-mode paste fetches are authorized with single-use X25519 challenges (60-second TTL) solved via ECDH, so no password or derived secret is ever transmitted or stored server-side
- ChaCha20Poly1305 authenticated encryption, 64 KB chunks with unique nonces
- HMAC-SHA256 for password validation (encryption key never leaves your device)
- Constant-time comparison against timing attacks
- No plaintext on server — even full compromise cannot expose data

## License

BSD-3-Clause
