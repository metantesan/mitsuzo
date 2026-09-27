# Mitsuzo

**Send it once. Keep the plaintext yours.**

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
boundary, chat history and ordinary pastebins leave too much behind. Mitsuzo is
designed for that handoff: encrypt locally, share a link, and let the paste
expire or burn after it is read.

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
recipient's public account key, so only that recipient can decrypt it. The
account is an encryption identity, not a general sign-up requirement for using
Mitsuzo.

### What the server sees

| Stored by the server | Kept on your device |
| --- | --- |
| Ciphertext and delivery metadata | Plaintext and password |
| Expiry and access-limit state | Encryption keys |
| Minimum data needed to serve the link | Browser/CLI decryption step |

## Highlights

- Client-side ChaCha20Poly1305 encryption with Argon2id key derivation
- Envelope encryption, so changing a password does not re-encrypt the content
- Chunked encryption and upload for files up to 1 GB
- TTL expiry, try-count limits, and cryptographic burn-after-reading receipts
- Optional zero-knowledge accounts based on a BIP39 seed phrase and X25519
- Encrypted paste delivery to another account
- Browser UI, Rust CLI, Docker image, and English/Persian localization
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
mitsuzo create --file document.pdf
mitsuzo get 123456 --output decrypted.pdf
mitsuzo passwd 123456
mitsuzo account register --name alice
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

1. The client derives keys from a password using Argon2id.
2. A random content key encrypts the paste with ChaCha20Poly1305.
3. The content key is wrapped by a password-derived key.
4. Only ciphertext and protected metadata are uploaded.
5. The client derives the key again when the recipient opens the link.

The server cannot recover the plaintext from the stored ciphertext alone. This
is a security design, not a promise that every deployment or client device is
safe. Read the [security documentation](SECURITY.md) and the in-app
documentation before using Mitsuzo for high-value secrets.

## Self-hosting

The backend is an Axum server with persistent metadata storage and filesystem
content storage. The frontend is a Dioxus WebAssembly application.

```bash
git clone https://github.com/metantesan/mitsuzo.git
cd mitsuzo
cargo build --release -p backend -p cli
```

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
