# Security policy

Mitsuzo is designed so that the server does not receive paste plaintext or
user passwords. That reduces the impact of a server compromise, but it does
not make every deployment or client device automatically secure.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Contact the maintainer
privately at `me@metantesan.com` with:

- a description of the issue and its impact;
- the affected version or commit;
- clear reproduction steps or a proof of concept;
- any suggested mitigation.

Please allow time for investigation and a fix before public disclosure.

## Deployment guidance

- Serve the application over HTTPS.
- Keep passwords and generated links out of logs, analytics, and screenshots.
- A self-hosted deployment is responsible for backups, access control, TLS,
  storage permissions, and dependency updates.
- Mitsuzo has not undergone an independent third-party security audit yet.

## Threat model

Mitsuzo is intended to protect paste plaintext from the storage server and its
database backups. The browser or CLI encrypts content before upload, and the
server receives ciphertext plus the metadata needed to serve, expire, and
rate-limit a paste.

Mitsuzo does not protect against:

- a compromised browser, operating system, or CLI binary;
- a stolen password, seed phrase, or shared paste link;
- malicious JavaScript or a modified client served before encryption;
- traffic analysis, availability attacks, or all metadata leakage;
- weak passwords that can be guessed offline if the attacker obtains a paste.

Use a strong password, verify the client source when handling high-value
secrets, and self-host if the public service's operational trust boundary is
not appropriate for your use case.
