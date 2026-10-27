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
  - `ssh`: warn on `AllowTcpForwarding yes` / `PermitTunnel yes`
  - `kernel`: `kernel.unprivileged_bpf_disabled`, `kernel.yama.ptrace_scope`
  - `services`: Redis/Memcached/MongoDB bound to all interfaces without auth
  - `tls`: certificates using SHA-1 or RSA < 2048
- **Windows checks** — `windows/anzen.ps1` is newer and smaller: e.g. LAPS,
  Windows Hello / PIN policy, Attack Surface Reduction rules, SMB null sessions,
  scheduled tasks running as SYSTEM from writable paths.
- **Distrusted certificates** — when a CA is compromised or distrusted, add its
  fingerprints to `lib/data/distrusted-certs.tsv` (one line per certificate,
  with a reference link).
- **Docs** — clearer explanations of why a finding matters, translations of
  the README.

## Bigger features

- **Windows parity** — HTML/TXT/SARIF reports, notifications and `-Remote`
  (WinRM/SSH) in the PowerShell edition
- **macOS edition**
- **Kubernetes depth** — RBAC, pod security, network policies (beyond the
  current runtime checks)
- **Plugin catalogue** — shareable `CUSTOM_CHECKS_DIR` modules (NAS, Proxmox,
  reverse proxies, Home Assistant…)
- **Packaging** — `.deb`/`.rpm`/AUR packages, Homebrew, Scoop/winget for Windows
- **Dashboard** — per-finding history ("first seen", "flapping"), fleet filter
  by tag, export to CSV

Have an idea that's not here? Open an issue or start a discussion.
