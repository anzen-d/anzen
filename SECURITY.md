# Security Policy

Anzen runs as root and executes remediation commands that users copy, so bugs
can have security impact.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") with:

- what an attacker can achieve and under which conditions,
- steps or a minimal proof of concept,
- the anzen version (`anzen.sh --version`) and platform.

You will get an acknowledgement within a week. Fixes are released as soon as
possible and credited in the changelog unless you prefer otherwise.

## Verifying releases

Release tarballs come with a SHA-256 checksum and a signed build provenance
attestation; see [docs/installation.md](docs/installation.md#verify-a-release).
The network connections anzen makes, and `--offline`, are listed in the same
file.

## Scope

In scope: command injection, unsafe temp files or symlink handling, privilege
escalation through anzen's files (config, accept file, custom checks, history),
remote mode (`--remote`) issues, unsafe remediation commands, dashboard XSS.

Out of scope: findings anzen reports about *your* system, and the intended
behaviour of the active pentest modules, which must only be pointed at systems
you own or are authorised to test.
