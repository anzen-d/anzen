# Roadmap and how to help

Anzen is young and contributions shape where it goes. Pick anything below,
open an issue saying you're on it, and see [CONTRIBUTING.md](CONTRIBUTING.md).

## Good first contributions

Small, self-contained, no deep knowledge of the codebase needed.

- **Test on your distro** — run `sudo ./anzen.sh` on something we don't test
  in CI yet (Raspberry Pi OS, Proxmox, TrueNAS SCALE, Amazon Linux, NixOS,
  Gentoo, Void) and report crashes or false positives.
- **Report false positives** — a finding that is wrong on your system is a
  bug. Use the "False positive" issue template.
- **Improve a remedy** — many findings print a fix command; make them more
  precise for a distro family, or add one where it is missing.
- **New single checks** in an existing module, for example:
  - `services`: Kafka answering without SASL
  - `tls`: wildcard certificates reused on many hosts
- **New plugins** for the [plugin catalogue](plugins/README.md): Proxmox,
  Home Assistant, Traefik/Caddy, NAS (Synology, TrueNAS)
- **Windows checks** — `windows/anzen.ps1` is newer and smaller: e.g. Windows
  Hello / PIN policy, Defender tamper protection, SMB share permissions.
- **Distrusted certificates** — when a CA is compromised or distrusted, add its
  fingerprints to `lib/data/distrusted-certs.tsv` (one line per certificate,
  with a reference link).
- **Docs** — clearer explanations of why a finding matters, translations of
  the README.

## Bigger features

- **Windows parity** — CVE checks, `-Remote` over SSH (WinRM is done), and
  auditing Windows hosts from the Linux `--remote` fleet
- **macOS parity** — standalone notifications, screen-lock policy per user,
  startup security (Apple silicon `bputil`), configuration-profile payload review
- **Kubernetes depth** — RBAC, pod security, network policies (beyond the
  current runtime checks)
- **Plugin catalogue** — started in `plugins/` (backup age, remote certificate
  expiry, Nginx Proxy Manager, enabled with `PLUGINS=`); more plugins welcome
- **Packaging** — an apt/dnf repository, AUR, winget (`.deb`/`.rpm`, Homebrew and Scoop are done)
- **Dashboard** — per-finding history view across hosts (the tag filter is done)
- **Compliance** — finer control mapping (per message), CIS Benchmark section
  numbers per distro

Have an idea that's not here? Open an issue or start a discussion.
