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
