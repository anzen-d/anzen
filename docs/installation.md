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

---

[← Back to README](../README.md)
