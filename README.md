# Mitsuzo

**Send it once. Keep the plaintext yours.**

> **Hybrid post-quantum recipient encryption:** New pastes sent to an account
> use X-Wing (ML-KEM-768 + X25519) to protect the content key. Password pastes
> do not use post-quantum key exchange, and account sign-in still uses X25519.

Mitsuzo is an open-source, self-hostable handoff for secrets and short-lived
files. It encrypts in the browser or CLI before anything is uploaded, so the
server stores ciphertext instead of your plaintext.

[![CI](https://github.com/metantesan/mitsuzo/actions/workflows/ci.yml/badge.svg)](https://github.com/metantesan/mitsuzo/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/metantesan/mitsuzo)](https://github.com/metantesan/mitsuzo/releases)
[![Docker image](https://img.shields.io/badge/docker-ghcr.io%2Fmetantesan%2Fmitsuzo-blue)](https://github.com/metantesan/mitsuzo/pkgs/container/mitsuzo)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green)](LICENSE)

[Live demo](https://mitsuzo.metantesan.com) · [Documentation](https://mitsuzo.metantesan.com/docs) · [Releases](https://github.com/metantesan/mitsuzo/releases)

## Why Mitsuzo?

When a password, `.env` file, recovery code, or private note needs to cross a
boundary, chat history and ordinary pastebins leave too much behind. Mitsuzo
encrypts locally, supports hybrid post-quantum recipient delivery, and lets
the paste expire or burn after it is read.

No account is required for the basic flow. When you need a private deployment,
run the same project yourself with Docker and keep the storage under your
control.

## The 30-second flow

1. Drop text or a file into the web app, or pipe a secret to the CLI.
2. Mitsuzo encrypts it locally before upload and gives you a shareable link.
3. Choose an expiry, try limit, or burn-after-reading so the handoff does not
   become permanent storage.

### Two ways to share

**Password mode** is the fast path: no account is needed. Choose a password,
send the link, and the recipient enters that password to decrypt the paste.

**Recipient mode** is for a known person. The sender encrypts the paste to the
recipient's public account key using X-Wing, a hybrid KEM combining ML-KEM-768
and X25519. New recipient pastes use this hybrid exchange; existing X25519
recipient pastes remain readable. The account is an encryption identity, not
a general sign-up requirement for using Mitsuzo.

### Post-quantum protection, precisely

X-Wing is used to establish a shared secret for recipient-mode key wrapping.
HKDF-SHA256 derives the key that wraps the random content-encryption key. The
paste body itself is encrypted in chunks with XChaCha20-Poly1305 by default;
ChaCha20-Poly1305 is also available. Password mode does not use X-Wing, and
new account IDs are derived from their X-Wing public keys. Account sign-in
still uses single-use X25519 challenges. When a legacy account passes its
X25519 challenge, the client offers to use its seed phrase locally to create a
new X-Wing ID; the phrase is never sent to the server. The legacy ID remains
available for older pastes but cannot receive new recipient pastes. Mitsuzo
has hybrid post-quantum key exchange for new recipient pastes, not post-quantum
protection for every feature or every key exchange in the application.

### What the server sees

| Stored by the server | Kept on your device |
| --- | --- |
| Ciphertext and delivery metadata | Plaintext and password |
| Expiry and access-limit state | Encryption keys |
| Minimum data needed to serve the link | Browser/CLI decryption step |

## Highlights

- Hybrid X-Wing recipient key exchange (ML-KEM-768 + X25519) for new account-addressed pastes
- XChaCha20-Poly1305 content encryption by default; ChaCha20-Poly1305 is selectable
- Argon2id password key derivation and envelope encryption for password pastes
- Chunked encryption and upload for files up to 1 GiB
- TTL expiry, try-count limits, and cryptographic burn-after-reading receipts
- Zero-knowledge accounts derived from a BIP39 seed phrase, with X-Wing public keys defining new account IDs
- Browser UI, Rust CLI, Docker image, browser encryption benchmark, and English/Persian localization
- ETag revalidation for static assets, plus baseline browser security headers
- BSD-3-Clause license and a documented self-hosting path

## Good fits

- Sharing a password or API token with a teammate
- Sending a short-lived `.env`, config file, or recovery code
- Moving a private note between devices without leaving it in chat history
- Running an encrypted paste service on infrastructure you control

## Try it locally

```bash
docker run --rm -p 3030:3030 ghcr.io/metantesan/mitsuzo:latest
```

Open <http://localhost:3030> and create a paste. You can also try the
[public live demo](https://mitsuzo.metantesan.com). For a safe, short-lived
self-hosted demo deployment, use the restricted demo mode:

```bash
docker run --rm -p 3030:3030 \
  -e MITSUZO_DEMO_MODE=1 \
  ghcr.io/metantesan/mitsuzo:latest
```

Demo mode caps the TTL at one minute and the upload size at 5 MB.

## CLI

Release binaries are published for Linux, macOS, and Windows on the
[Releases page](https://github.com/metantesan/mitsuzo/releases).

New pastes use XChaCha20-Poly1305 by default. The web app and CLI also let you
choose ChaCha20-Poly1305. These ciphers encrypt paste content; they are
separate from the key exchange used to protect the content key. New recipient
pastes use hybrid X-Wing (ML-KEM-768 + X25519), while password pastes use the
password-derived key. Updated clients and servers are required for the newer
formats; existing paste versions remain readable by compatible clients.

### Install a pre-built binary

For Linux, macOS, and other Unix-like systems, use the installer:

```bash
curl -fsSL https://mitsuzo.metantesan.com/install.sh -o /tmp/mitsuzo-install.sh
sh /tmp/mitsuzo-install.sh
```

The installer detects your platform, downloads the matching release, verifies
`checksums.txt`, and installs to `~/.local/bin`. Set
`MITSUZO_INSTALL_DIR=/usr/local/bin` if you want a different destination and
have permission to write there. The release page also includes builds for Linux ARM64,
macOS Apple Silicon, Windows x86_64, and Windows ARM64. Every release includes
`checksums.txt` for verification.

```bash
echo "secret message" | mitsuzo create
echo "secret message" | mitsuzo create --cipher chacha
mitsuzo create --file document.pdf
mitsuzo create --cipher chacha --file document.pdf
mitsuzo get 123456 --output decrypted.pdf
mitsuzo passwd 123456
mitsuzo account register --name alice
mitsuzo config set base-url https://your-server.example
```

To use a remote server, pass its URL before the command:

```bash
mitsuzo --base-url https://mitsuzo.metantesan.com create
```

You can also save the URL in `config.yml` under your platform's config
directory:

```yaml
base_url: https://mitsuzo.metantesan.com
```

## How the security model works

1. The client generates a random content key and encrypts the paste in chunks
   with the selected cipher (XChaCha20-Poly1305 by default).
2. In password mode, Argon2id derives password keys and HKDF separates their
   uses; a derived key wraps the content key.
3. In recipient mode, X-Wing (ML-KEM-768 + X25519) establishes a shared secret
   and HKDF derives the key that wraps the content key.
4. Only ciphertext and the metadata needed to deliver and enforce paste
   settings are uploaded.

New pastes use the explicitly marked BLAKE3 format. The client incrementally
hashes plaintext chunks as it encrypts them, then stores the 32-byte digest in
an encrypted EOF commitment under the content key. The commitment also binds
the paste ID, protocol version, chunk count, plaintext length, and delivery
metadata. Readers verify the commitment and recompute the digest from decrypted
chunks before exposing plaintext. New clients can still read older formats,
which predate this EOF commitment and cannot provide equivalent truncation
detection.

Changing a password re-wraps the content key; it does not encrypt or upload the
paste body again.

The server cannot recover plaintext from stored ciphertext alone. This does
not protect against a compromised client, a compromised device, or a server
that serves modified client code. Read the [security policy](SECURITY.md) for
the scope and limitations of the security model.

## Browser benchmark and transfer progress

The web app includes a `/benchmark` page that compares single-threaded browser
encryption and decryption throughput for ChaCha20-Poly1305 and
XChaCha20-Poly1305. It can run up to 1 GiB and reports the measured cipher
throughput; it does not measure file reading, upload, network, or server time.
Paste creation shows its current stage, transferred bytes, and throughput, with
an option to cancel an in-progress upload.

## Self-hosting

The backend is an Axum server with SQLite metadata storage and filesystem
ciphertext storage. The frontend is a Dioxus WebAssembly application. Static
assets support ETag revalidation; the server sends baseline security headers
and an enforcing Content Security Policy. The policy blocks inline scripts,
allows WebAssembly compilation, and permits inline style attributes for the
dynamic UI.

```bash
git clone https://github.com/metantesan/mitsuzo.git
cd mitsuzo
cargo build --release -p backend -p cli
```

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MITSUZO_DEMO_MODE` | off | Cap TTL at 60s and uploads at 5 MiB (1, true, yes, on) |
| `MITSUZO_MAX_TTL_SECONDS` | 43200 | Maximum paste TTL |
| `MITSUZO_MAX_FILE_SIZE_BYTES` | 1073741824 | Maximum paste/file size |
| `MITSUZO_TRUST_PROXY` | off | Trust `X-Forwarded-For`/`X-Real-IP` when resolving the client IP for rate limiting. Enable only behind a proxy you control. |
| `MITSUZO_ALLOWED_ORIGINS` | unset | Comma-separated browser origins allowed to call the API cross-origin. Empty means same-origin only. |

Behind a reverse proxy, set `MITSUZO_TRUST_PROXY=1` so rate limiting keys on
the real client address; otherwise every request is attributed to the proxy.
The server never reflects arbitrary origins in CORS responses unless they are
listed in `MITSUZO_ALLOWED_ORIGINS`.

See the in-app self-hosting guide for configuration and the
[contribution guide](CONTRIBUTING.md) for development checks.

## Project layout

```text
crates/backend    Axum HTTP server, rate limiting, storage, and API
crates/frontend   Dioxus WebAssembly client
crates/cli        Rust command-line client
crates/types      Shared request and response types
crates/utils      Cryptographic and key-management primitives
crates/migration  Database migrations
```

## Contributing and security

Bug reports, documentation, tests, and security reviews are welcome. Start
with [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately
according to [SECURITY.md](SECURITY.md).

## License

Mitsuzo is released under the [BSD-3-Clause license](LICENSE).
