# Mitsuzo

**Share secrets and files privately. The server never sees your plaintext.**

Mitsuzo is a zero-knowledge, self-hostable encrypted pastebin for sending
passwords, snippets, documents, and other short-lived files. Encryption happens
in the browser or CLI before anything is uploaded.

[![CI](https://github.com/metantesan/mitsuzo/actions/workflows/ci.yml/badge.svg)](https://github.com/metantesan/mitsuzo/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/metantesan/mitsuzo)](https://github.com/metantesan/mitsuzo/releases)
[![Docker image](https://img.shields.io/badge/docker-ghcr.io%2Fmetantesan%2Fmitsuzo-blue)](https://github.com/metantesan/mitsuzo/pkgs/container/mitsuzo)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green)](LICENSE)

[Live demo](https://mitsuzo.metantesan.com) · [Documentation](https://mitsuzo.metantesan.com/docs) · [Releases](https://github.com/metantesan/mitsuzo/releases)

## Why Mitsuzo?

Regular pastebins and chat messages are convenient, but the service can often
read, retain, or index what you send. Mitsuzo keeps the plaintext and password
on your device. The server stores encrypted data, delivery metadata, and the
minimum state needed to enforce expiry and access limits.

## Highlights

- Client-side ChaCha20Poly1305 encryption with Argon2id key derivation
- Envelope encryption, so changing a password does not re-encrypt the content
- Chunked encryption and upload for files up to 1 GB
- TTL expiry, try-count limits, and cryptographic burn-after-reading receipts
- Optional zero-knowledge accounts based on a BIP39 seed phrase and X25519
- Encrypted paste delivery to another account
- Browser UI, Rust CLI, Docker image, and English/Persian localization
- BSD-3-Clause license and a documented self-hosting path

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

```bash
echo "secret message" | mitsuzo create
mitsuzo create --file document.pdf
mitsuzo get 123456 --output decrypted.pdf
mitsuzo passwd 123456
mitsuzo account register --name alice
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
