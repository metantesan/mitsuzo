# Security policy

Mitsuzo is designed so that the server does not receive paste plaintext or
user passwords. That reduces the impact of a server compromise, but it does
not make the project or its deployment automatically secure.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Contact the maintainer
privately at `me@metantesan.com` with:

- a description of the issue and its impact;
- the affected version or commit;
- clear reproduction steps or a proof of concept;
- any suggested mitigation.

You will receive an acknowledgement as soon as practical. Please allow time
for investigation and a fix before publicly disclosing the issue.

## Scope and limitations

- Always verify that the web application is served over HTTPS.
- Keep passwords and generated links out of logs, analytics, and screenshots.
- A self-hosted deployment is responsible for its own backups, access control,
  TLS configuration, and dependency updates.
- Mitsuzo has not undergone an independent third-party security audit yet.
