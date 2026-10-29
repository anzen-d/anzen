# Installation


## Requirements

| Dependency | Notes |
|-----------|-------|
| `bash 4.2+` | Available on all modern Linux distros |
| `sudo` / root | Passwordless sudo recommended; script warns and continues without it |
| `ss`, `find`, `stat`, `awk`, `grep`, `sysctl` | Standard on all distros |
| `whiptail` or `dialog` | TUI only — `apt install whiptail` / `yum install newt` |
| `curl` | Notifications, heartbeat, `images` upstream check, HTTP probes |
| `trivy` | Optional — `cve` module ([trivy.dev](https://trivy.dev)); without it, `debsecan` is used on Debian |
| `docker` / `podman` | Optional — container modules (`docker_security`, `images`, `cve` image scans) |
| `ssh` | `--remote` only — key-based access to the audited hosts |

## Installation

```bash
git clone https://github.com/anzen-d/anzen.git
cd anzen
chmod +x anzen.sh anzen-tui.sh
```

Or use the installer (copies to `/usr/local/bin` and installs shell completions):

```bash
sudo ./install.sh
```

## Verify a release

Anzen runs as root, so check what you run. Every
[release](https://github.com/anzen-d/anzen/releases) has a source tarball, its
SHA-256 checksum and a signed build provenance attestation (Sigstore, created
by the release workflow from the tagged commit):

```bash
v=0.15.0
curl -LO https://github.com/anzen-d/anzen/releases/download/v$v/anzen-$v.tar.gz
curl -LO https://github.com/anzen-d/anzen/releases/download/v$v/anzen-$v.tar.gz.sha256
sha256sum -c anzen-$v.tar.gz.sha256
gh attestation verify anzen-$v.tar.gz --repo anzen-d/anzen   # built by this repo's workflow
tar xzf anzen-$v.tar.gz && cd anzen-$v
```

## Network connections

Anzen makes no network connections except these, and `--offline` turns all of
them off:

| What | Where | Module / setting |
|------|-------|------------------|
| Public IP lookup | api.ipify.org, ifconfig.me | `system` |
| CISA KEV catalog (cached 24 h) | cisa.gov (`KEV_URL`) | `cve`, `KEV_CHECK` |
| trivy vulnerability database | trivy's mirrors | `cve` |
| Newer image digests (HEAD requests) | the image's registry | `images`, `IMAGE_CHECK_UPDATES` |
| Notifications and heartbeat | only what you configure | `NOTIFY_*`, `HEARTBEAT_URL` |

The active `pentest` modules connect to localhost and to `--target`, and only
when you run them. Fleet mode (`--remote`) connects to the hosts you name, over
SSH.

---

[← Back to README](../README.md)
