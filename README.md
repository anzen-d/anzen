# 安全 Anzen — Linux & Windows Security Audit

Anzen audits Linux and Windows hosts for security problems: system hardening,
container hygiene, known CVEs and exposed services. It reports what is wrong,
how to fix it, and what changed since the last run, for one host or a fleet.
The Linux edition needs only Bash and standard tools (optional extras such as
trivy add features), so it runs on
anything from a Raspberry Pi to a Proxmox node.

![Anzen dashboard](docs/img/dashboard.png)

- **20+ check modules** — SSH, kernel sysctls, users, file permissions, secrets,
  systemd sandboxing, TLS, firewall, Docker/Podman/LXD/k8s, image freshness,
  and CVEs in host packages and every running container image (via trivy).
- **Windows edition** (`windows/anzen.ps1`) with the same reports and IDs.
- **Fleet mode** — `--remote=host1,host2` audits hosts over SSH without
  installing anything there.
- **Stable finding IDs**, accepted risks with expiry dates, per-section scores,
  baseline diffs, and **alerts only for new problems** (ntfy or any command).
- **History and a static dashboard** for every host, plus HTML, TXT, JSON and
  SARIF reports and a ready-to-run remediation script.
- Tested on Debian, Ubuntu, Fedora, Rocky, Alpine, Arch and openSUSE, and on
  Windows PowerShell 5.1.

> The `pentest` and `pentest_external` modules actively probe ports and URLs.
> Only point them at systems you own or are explicitly authorised to test.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Interactive TUI](#interactive-tui)
- [Modules](#modules)
- [Pentesting](#pentesting)
- [Report Formats](#report-formats)
- [Severity Levels](#severity-levels)
- [Exit Codes](#exit-codes)
- [Configuration](#configuration)
- [Baseline & Diff](#baseline--diff)
- [Accepted Risks](#accepted-risks)
- [History & Dashboard](#history--dashboard)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Custom Checks](#custom-checks)
- [Remediation](#remediation)
- [Windows](#windows)
- [How Anzen compares](#how-anzen-compares)
- [Remote Auditing](#remote-auditing)
- [Scheduling](#scheduling)
- [CI/CD Integration](#cicd-integration)

---

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

---

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

## Quick Start

```bash
# Full audit — terminal output only
sudo ./anzen.sh

# Full audit + HTML report
sudo ./anzen.sh --html

# Interactive TUI
./anzen-tui.sh
```

---

## CLI Usage

```
./anzen.sh [OPTIONS]
```

### Output Options

| Flag | Description |
|------|-------------|
| `--html` | HTML report → `reports/anzen_TIMESTAMP.html` |
| `--txt` | Plain-text report → `reports/anzen_TIMESTAMP.txt` |
| `--json` | JSON report → `reports/anzen_TIMESTAMP.json` |
| `--output=FILE` | Override output path (applies to first enabled format) |
| `--remediate` | Generate `reports/remediate_TIMESTAMP.sh` from findings |

### Filtering

| Flag | Description |
|------|-------------|
| `--check=MODULE` | Run only the specified module — repeatable |
| `--quiet`, `-q` | Suppress `INFO` lines (show `FAIL`/`WARN`/`OK` only) |
| `--no-color` | Disable ANSI colour output |

### Advanced

| Flag | Description |
|------|-------------|
| `--parallel`, `-p` | Run all modules in parallel |
| `--baseline` | Save this run as the baseline for future diffs |
| `--diff` | Compare against saved baseline — exits `2` on regressions |
| `--config=FILE` | Load config from `FILE` instead of `anzen.conf` |
| `--remote=HOSTS` | Audit one or more hosts over SSH: `[user@]host[,...]` |
| `--schedule=FREQ` | Install cron job (`daily`\|`weekly`\|`monthly`) |
| `--history=DIR` | Save this run to `DIR/<host>/` (overrides `HISTORY_DIR`) |
| `--dashboard=FILE` | Build the static dashboard from the history dir and exit |
| `--version`, `-v` | Print version and exit |
| `--help`, `-h` | Show help |

### Pentesting

| Flag | Description |
|------|-------------|
| `--target=HOST/URL` | External endpoint to pentest (own systems only) |
| `--wan` | Also scan the WAN/public IP for internet-exposed ports |
| `--resolve-to=IP` | Force all HTTP checks and port scan to this IP — simulates internet perspective when DNS resolves to a LAN address |
| `--remote-pentest=USER@HOST` | Run the external pentest from a remote SSH host for a true outside-internet view |

### Examples

```bash
# Full audit, all three report formats
sudo ./anzen.sh --html --txt --json

# Only SSH and kernel checks, quiet mode
sudo ./anzen.sh --check=ssh --check=kernel --quiet

# Generate reports + remediation script
sudo ./anzen.sh --html --remediate

# CI run — exits 1 on any FAIL, JSON for ingestion
sudo ./anzen.sh --quiet --json --output=/tmp/audit.json

# Pipe to log without colour
sudo ./anzen.sh --no-color | tee /var/log/anzen.log

# Parallel run for speed on large systems
sudo ./anzen.sh --parallel --html

# Audit a remote host, save HTML locally
sudo ./anzen.sh --remote=admin@10.0.0.5 --html --output=/tmp/remote.html

# Save baseline, then on next run diff against it
sudo ./anzen.sh --baseline
sudo ./anzen.sh --diff      # exits 2 if anything regressed

# Local self-pentest (ports, banners, HTTP exposure)
./anzen.sh --check=pentest

# Pentest your own public endpoint
./anzen.sh --check=pentest_external --target=https://example.com

# Pentest + check what's actually internet-exposed on the WAN IP
./anzen.sh --check=pentest_external --target=https://example.com --wan

# Simulate internet perspective when DNS resolves to a LAN IP
./anzen.sh --check=pentest_external --target=https://example.com --resolve-to=1.2.3.4

# True external pentest — run from a remote VPS
./anzen.sh --remote-pentest=user@vps.example.com --target=https://example.com
```

---

## Interactive TUI

`anzen-tui.sh` is a full interactive terminal UI built on `whiptail`/`dialog` that wraps all CLI options.

```bash
./anzen-tui.sh [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-h` | Show help |
| `-v` | Print version |
| `-n` | Force plain-text `select` menu (no whiptail/dialog) |
| `-t SECONDS` | Timeout for "Press Enter" prompts (default: 30) |

### Main Menu

```
  安全  Anzen 0.7.2 — Linux Security Audit

  Modules: 18/18   Formats: (none)
  Options: (none)
  Advanced: (none)

  ┌─────────────────────────────────────────────┐
  │  1  Select Modules       (toggle checks)    │
  │  2  Output Formats       (HTML / TXT / JSON)│
  │  3  Options              (quiet, parallel…) │
  │  4  Advanced             (file, remote, …)  │
  │  5  View Reports         (browse reports/)  │
  │  6  About                                   │
  │  7  Run Audit                               │
  └─────────────────────────────────────────────┘
```

### Features

- **Module checklist** — toggle individual checks; All On / All Off shortcuts
- **Format selector** — HTML, TXT, JSON checkboxes
- **Options** — quiet, no-color, parallel, remediate, baseline, diff
- **Advanced settings** — output file (with directory writability check), remote SSH host (with format validation), config file (with existence check + `realpath` resolution), cron schedule
- **Live output** — `dialog` streams audit output in a scrolling `--progressbox` widget; `whiptail` outputs directly to terminal
- **Post-run report viewer** — opens TXT/JSON in `less`, HTML via `xdg-open`
- **About dialog** — hostname, OS, script paths, module count
- **Plain-text fallback** — activates automatically when stdin/stdout is not a TTY, or with `-n`; uses bash `select` menu
- **Auto-continue** — "Press Enter" prompts time out after `-t` seconds (default 30)
- **Syslog** — every audit run is logged via `logger -t anzen-tui`

---

## Modules

| Module | CLI name | What it checks |
|--------|----------|----------------|
| System Info | `system` | Hostname, OS, kernel, arch, uptime, CPU/memory/disk usage, public IP, running service count |
| Users & Accounts | `users` | Passwordless sudo (`NOPASSWD`), UID 0 accounts, empty passwords, world-writable home dirs, password aging policy, PAM lockout config, sudo logging |
| SSH Hardening | `ssh` | `PermitRootLogin`, `PasswordAuthentication`, port, `MaxAuthTries`, `X11Forwarding`, `ClientAliveInterval`, `LoginGraceTime`, `AllowUsers`/`AllowGroups`, ciphers/MACs/KexAlgorithms, `authorized_keys` permissions |
| Firewall & Ports | `network` | UFW/firewalld/nftables/iptables status, high-risk open ports (IPv4 + IPv6), RPC portmapper |
| Advanced Network | `network2` | Promiscuous interfaces, IPv6 privacy extensions, tunnel/VPN interfaces |
| Package Updates | `packages` | Pending security/package updates, package list staleness, unattended-upgrades daemon |
| File Permissions | `files` | Critical file permissions (`/etc/passwd`, `/etc/shadow`, etc.), world-writable files, unexpected SUID/SGID binaries |
| Secrets & Credentials | `secrets` | Private key permissions, `.env` files, AWS credential files, `.netrc` files |
| Systemd Hardening | `systemd_hardening` | Per-service hardening options (`PrivateTmp`, `NoNewPrivileges`, `ProtectSystem`, etc.), services running as root |
| TLS Certificates | `tls` | Certificate expiry (files + live ports), expired/near-expiry certs |
| Compilers & Tools | `compiler` | Compiler/build tools present, offensive security tools (nmap, metasploit, etc.), packet capture tools |
| PATH Security | `path_check` | Empty/relative PATH entries, `.` in PATH, world-writable PATH dirs, `LD_PRELOAD` set, potential PATH injection in shell configs |
| Kernel Modules | `modules` | `modules_disabled` sysctl, risky loaded modules, module blacklist entries, `usb-storage` |
| Services | `services` | Docker group membership, privileged/host-network containers, fail2ban/CrowdSec, exposed databases, Samba/SMB |
| Login History | `logins` | Root crontab contents, cron file permissions, recent/failed login history, account password expiry |
| Kernel Hardening | `kernel` | ASLR, SYN cookies, IP forwarding, ICMP redirects, source routing, martian packet logging, core dumps, AppArmor/SELinux status |
| Audit Daemon | `auditd` | auditd running + rules loaded, NTP/time sync, TCP wrappers, rkhunter/chkrootkit |
| Container Security | `docker_security` | Docker, Podman, nerdctl, LXD, LXC, Kubernetes — runtime-specific security checks |
| Container Images | `images` | Running images: age, `:latest`/untagged, containers not recreated after a pull, newer digest upstream |
| Vulnerabilities | `cve` | Known CVEs in host packages and running container images (needs trivy) |
| Local Pentest | `pentest` | Active self-pentest: port scan, service banner grabbing, local HTTP sensitive path enumeration, HTTP security headers |
| External Pentest | `pentest_external` | Active pentest of a remote endpoint (requires `--target`): DNS recon, port scan with service fingerprinting, TLS/SSL analysis, HTTP security headers, content-aware sensitive path enumeration, CORS, HTTP methods, open redirect, clickjacking, information disclosure |

---

## Pentesting

> **Only test systems you own or have explicit written permission to test.**

Anzen includes two active pentesting modules that go beyond passive audit — they probe hosts for real vulnerabilities.

### Local self-pentest (`pentest`)

Actively scans the local host:

- **Port scan** — full TCP scan via `nmap` (or bash `/dev/tcp` fallback)
- **Service banners** — grabs banners from open ports, flags version disclosure
- **HTTP exposure** — probes local web services for sensitive paths (`/.git`, `/.env`, `/admin`, Spring Actuator, Swagger, etc.)
- **HTTP security headers** — checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy on all local HTTP ports

```bash
./anzen.sh --check=pentest
```

### External pentest (`pentest_external`)

Actively probes a remote endpoint specified with `--target`:

- **DNS recon** — A records, MX, TXT, SPF, DMARC, zone transfer (AXFR) attempt
- **Port scan** — `nmap` top-1000 or TCP fallback; service fingerprinting identifies the real application on each port (not just port number)
- **LAN/WAN detection** — automatically detects when DNS resolves to a private IP and reports scope; detects WAN IP
- **TLS/SSL** — certificate expiry, weak protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4/NULL/EXPORT/DES)
- **HTTP security headers** — full header audit including cookie flags and version disclosure
- **Sensitive path enumeration** — 60+ paths checked with a two-stage filter:
  1. **Catch-all baseline** — probes a random canary URL first; responses matching the catch-all size are silently skipped
  2. **Content-aware secret scanning** — unique responses are scanned for actual secrets (private keys, passwords, DB connection strings, AWS keys, JWTs, tokens) before raising a FAIL
- **CORS** — tests for wildcard and reflected-origin misconfigurations
- **HTTP methods** — flags TRACE/TRACK, PUT/DELETE exposure
- **Open redirect** — tests 10 common redirect parameters
- **Clickjacking** — checks X-Frame-Options and CSP `frame-ancestors`
- **Information disclosure** — error page stack traces, robots.txt disallowed paths

```bash
# Basic external pentest
./anzen.sh --check=pentest_external --target=https://example.com

# Also scan the WAN/public IP for internet-exposed ports
./anzen.sh --check=pentest_external --target=https://example.com --wan

# Simulate internet perspective (DNS resolves to LAN — override to WAN IP)
./anzen.sh --check=pentest_external --target=https://example.com --resolve-to=1.2.3.4

# True external view — run the pentest from a remote VPS via SSH
./anzen.sh --remote-pentest=user@vps.example.com --target=https://example.com
```

### Secret scanner

The content-aware secret scanner runs on any response body that passes the catch-all filter. It detects:

| Pattern | Examples |
|---------|---------|
| Private keys | `BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY` |
| Credential fields | `password=`, `secret=`, `api_key=`, `client_secret=` |
| DB connection strings | `mysql://`, `postgres://`, `mongodb://`, `redis://` |
| AWS credentials | `AKIA...` access keys, `aws_secret_access_key` |
| JWT tokens | `eyJ...` three-part signed tokens |
| Bearer / Basic auth | Tokens in Authorization headers |
| htpasswd hashes | `$apr1$`, `{SHA}`, crypt(3) |
| PHP / Spring / WP secrets | `DB_PASSWORD`, `propertySources`, `table_prefix` |
| Slack / GitHub tokens | `xoxb-`, `ghp_`, `ghs_` |

---

## Report Formats

### Terminal
Colour-coded live output with section headers and a summary score card.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SSH Configuration             80%   FAIL 1   WARN 3
  Container Security             0%   FAIL 2   WARN 40

  Repeated:
    18× WARN No memory limit
    12× WARN Running as root
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FAIL: 3   WARN: 43   OK: 52   Score: 88%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Each section scores `100 - (FAILs × 10) - (WARNs × 3)`, minimum 0; the overall
score is the mean of the section scores, so one noisy section cannot pin the
whole host at 0%. Penalties are configurable via `anzen.conf`. Messages that
share a prefix (text before `:`) three or more times are grouped under
*Repeated*.

Every WARN/FAIL has a stable **finding ID** such as `container-security-9bdb5279`:
the section plus a hash of the message with volatile parts (percentages, sizes,
durations, counts) normalised. IDs are what `--diff` and the
[accept file](#accepted-risks) match on, and they appear in every report.

### HTML
Self-contained dark-theme report with collapsible sections, colour-coded findings, and a score card. No external dependencies — single file.

### Plain Text
Structured audit trail with section headers and tab-delimited findings. Suitable for archiving, email, or diffing.

### JSON
Machine-readable output:

```json
{
  "hostname": "server1", "os": "...", "kernel": "...", "date": "...",
  "summary": { "fail": 3, "warn": 43, "ok": 52, "info": 12, "score": 88 },
  "sections": [
    { "name": "SSH Configuration", "fail": 1, "warn": 3, "ok": 9, "score": 80 }
  ],
  "findings": [
    { "id": "ssh-configuration-1c0e5a7d", "level": "FAIL", "section": "SSH Configuration",
      "message": "PermitRootLogin: yes", "remedy": "..." }
  ]
}
```

### SARIF
SARIF 2.1.0 for GitHub/GitLab code scanning. Each result carries the finding ID
in `partialFingerprints.anzenFindingId/v1`, so alerts track across runs.

---

## Severity Levels

| Level | Meaning | Exit impact |
|-------|---------|-------------|
| `FAIL` | Security issue that should be fixed | Triggers exit code `1` |
| `WARN` | Potential risk or deviation from hardening best practice | Exit `1` only with `--strict` |
| `OK` | Check passed | — |
| `INFO` | Informational only — suppressed by `--quiet`. Also used for [accepted risks](#accepted-risks) | — |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit complete — no `FAIL` findings |
| `1` | One or more `FAIL` findings detected |
| `2` | Baseline diff detected regressions (`--diff` mode) |
| `255` | `--remote`: a host could not be reached or produced no report (worst code across hosts wins otherwise) |

With `--strict`, any `WARN` also exits `1`.

---

## Configuration

Copy `anzen.conf.example` to `anzen.conf` (or any path, then use `--config=FILE`) and adjust thresholds:

```bash
cp anzen.conf.example anzen.conf
```

| Key | Default | Description |
|-----|---------|-------------|
| `DISK_WARN_PCT` | `75` | Disk usage warn threshold (%) |
| `DISK_FAIL_PCT` | `90` | Disk usage fail threshold (%) |
| `MEM_WARN_PCT` | `75` | Memory usage warn threshold (%) |
| `MEM_FAIL_PCT` | `90` | Memory usage fail threshold (%) |
| `FAIL_LOGIN_OK` | `10` | Failed login count below which is OK |
| `FAIL_LOGIN_WARN` | `50` | Failed login count warn threshold |
| `SERVICE_COUNT_WARN` | `30` | Running service count warn threshold |
| `SERVICE_COUNT_FAIL` | `50` | Running service count fail threshold |
| `PASS_MAX_DAYS_WARN` | `90` | Max password age warn (days) |
| `TLS_WARN_DAYS` | `30` | TLS cert expiry warn (days) |
| `TLS_FAIL_DAYS` | `7` | TLS cert expiry fail (days) |
| `SCORE_FAIL_PENALTY` | `10` | Points deducted per FAIL |
| `SCORE_WARN_PENALTY` | `3` | Points deducted per WARN |
| `EXCLUDE_CHECKS` | — | Space-separated module names to skip |
| `CUSTOM_SUID_WHITELIST` | — | Additional SUID binaries to accept |
| `WW_FILE_CAP` | `50` | Cap on world-writable file findings |
| `EXCLUDE_PATHS` | — | Glob patterns excluded from world-writable scan (`dir/*` patterns are pruned, not walked) |
| `IMAGE_MAX_AGE_DAYS` | `180` | `images`: WARN for running images older than this |
| `IMAGE_CHECK_UPDATES` | `true` | `images`: compare with the registry digest (HEAD requests, no pulls) |
| `IMAGE_WARN_LATEST` | `true` | `images`: WARN for `:latest` / untagged images |
| `FAIL_AS_WARN` | — | Substrings; matching FAILs are downgraded to WARN |
| `ACCEPT_FILE` | `anzen.accept` | Accepted-risk file, see [Accepted Risks](#accepted-risks) |
| `HISTORY_DIR` | — | Save every run under `<dir>/<host>/` |
| `HISTORY_KEEP` | `52` | Runs kept per host |
| `DASHBOARD_FILE` | — | Rebuild this dashboard after every saved run |
| `NOTIFY_NTFY_URL` / `NOTIFY_CMD` | — | Notification target |
| `NOTIFY_ON` | `always` | `always`, `fail` or `regression` (new FAIL vs previous history run; never on a host's first run) |
| `NOTIFY_ON_FAIL_ONLY` | `false` | Legacy: `true` is the same as `NOTIFY_ON=fail` |
| `NOTIFY_NTFY_TOKEN` | — | Bearer token for the ntfy topic |
| `HEARTBEAT_URL` | — | Fetched after every run (dead-man switch) |
| `CUSTOM_CHECKS_DIR` | — | Directory of site-specific check modules |

---

## Baseline & Diff

Save a snapshot of the current findings, then detect regressions on future runs:

```bash
# Save baseline
sudo ./anzen.sh --baseline

# Later — diff against it (exits 2 if anything regressed)
sudo ./anzen.sh --diff

# Combine with JSON for machine-readable diff output
sudo ./anzen.sh --diff --json
```

The baseline is saved to `reports/.baseline.json`. A `FAIL` whose finding ID is
not in the baseline counts as a regression; a FAIL whose numbers changed (e.g.
disk 91% → 95%) keeps its ID and is not. Baselines from versions before 0.5.0
hold messages only — they are compared by message until you re-run `--baseline`.

---

## Accepted Risks

Some findings are intentional — Portainer needs the Docker socket. List them in
`anzen.accept` (or the file named by `ACCEPT_FILE`), one per line:

```
# ID                         expires     reason
container-security-9bdb5279  2027-01-31  Portainer needs the Docker socket to manage stacks
```

Take the ID from any report. Until the date passes, the finding is reported as
`INFO` with the reason and does not affect the score or exit code. Afterwards it
returns at its real level, marked "acceptance expired". The date is mandatory,
so nothing stays accepted forever. The file must be owned by you or root and
not world-writable — the same rule as `anzen.conf`.

---

## History & Dashboard

Keep every run and get a trend view across one or many hosts:

```bash
# Save runs to a history dir (or set HISTORY_DIR in anzen.conf)
sudo ./anzen.sh --history=/var/lib/anzen/history

# Build a static dashboard from it — one HTML file, no network access
./anzen.sh --history=/var/lib/anzen/history --dashboard=/var/lib/anzen/www/index.html
```

Runs land in `HISTORY_DIR/<host>/<timestamp>.json`; the newest `HISTORY_KEEP`
(default 52) are kept. Point several hosts at a shared directory for a fleet view.
Set `DASHBOARD_FILE` to rebuild the dashboard after every run.

The dashboard shows each host's score and change, a stale marker when the last
run is older than 8 days, the score trend, FAILs that are new or fixed since the
previous run, accepted risks expiring within 30 days, section scores and a
filterable findings table. It contains your findings, including file paths of
exposed secrets, so serve it read-only and behind authentication.

A typical unattended setup in `anzen.conf`:

```bash
HISTORY_DIR="/var/lib/anzen/history"
DASHBOARD_FILE="/var/lib/anzen/www/index.html"
NOTIFY_NTFY_URL="https://ntfy.example.com/alerts"
NOTIFY_ON=regression                       # only when a new FAIL appears
HEARTBEAT_URL="https://kuma.example.com/api/push/XXXX?status=up"
```

```bash
sudo ./anzen.sh --config=/etc/anzen/anzen.conf --parallel --schedule=weekly:04:30
```

---

## Vulnerability Scanning

With [trivy](https://trivy.dev) installed, the `cve` module checks for known
CVEs — PHP, Java, Node.js, Python, Go and OS packages alike:

- the **host** root filesystem (OS packages and installed language packages)
- every **running container image** (Docker or Podman), once per image

Each vulnerable package version is one finding — FAIL when any CVE is
CRITICAL, WARN for HIGH — listing the CVE count, up to three CVE IDs, the fixed
version and which containers use the image. trivy updates its vulnerability
database itself, so a weekly run with `NOTIFY_ON=regression` alerts you when a
new CVE is published for something you run.

```bash
sudo ./anzen.sh --check=cve            # host + images; can take 20+ min on a busy host
```

| Key | Default | Description |
|-----|---------|-------------|
| `CVE_SEVERITY` | `CRITICAL,HIGH` | Severities reported |
| `CVE_IGNORE_UNFIXED` | `true` | Only CVEs that already have a fixed version |
| `CVE_SCAN_IMAGES` | `true` | Also scan running container images |
| `CVE_TIMEOUT` | `60m` | Timeout per trivy run |
| `CVE_SKIP_DIRS` | system dirs | Dirs the host scan skips; add `/home` to skip dev checkouts |

---

## Custom Checks

Site-specific checks live outside the anzen tree. Set `CUSTOM_CHECKS_DIR` and
add `<name>.sh` files that define `run_<name>_check` using the same helpers as
the built-in modules:

```bash
# /etc/anzen/checks.d/backups.sh
run_backups_check() {
    section "Backups"
    local age=$(( ( $(date +%s) - $(stat -c %Y /srv/backup/last) ) / 86400 ))
    if [ "$age" -gt 2 ]; then
        fail "Last backup is $age days old"
        remedy "systemctl start backup.service"
    else
        ok "Last backup is $age days old"
    fi
}
```

They run with the other modules and can be selected with `--check=backups`.
Custom checks run as root, so each file must be owned by you or root and not
world-writable — otherwise it is skipped.

---

## Remediation

`--remediate` generates a shell script with fix commands for each `FAIL` finding that has a known remedy:

```bash
sudo ./anzen.sh --remediate
# Writes: reports/remediate_TIMESTAMP.sh

# Review before running
less reports/remediate_*.sh

# Apply
sudo bash reports/remediate_*.sh
```

---

## Windows

`windows/anzen.ps1` is the Windows edition (Windows PowerShell 5.1+ / PowerShell 7,
Windows 10/11 and Server 2016+). It uses the same finding IDs, scores,
accept-file format and JSON report, so Windows hosts show up in the same
history and dashboard as Linux hosts.

```powershell
# Elevated PowerShell
powershell -ExecutionPolicy Bypass -File .\windows\anzen.ps1 -Json
.\windows\anzen.ps1 -Check firewall,smb,rdp -Quiet
.\windows\anzen.ps1 -History \\server\anzen\history   # shared HISTORY_DIR for the dashboard
.\windows\anzen.ps1 -List                               # modules
```

| Module | Checks |
|--------|--------|
| `system` | Pending reboot, uptime, disk usage |
| `updates` | Days since last installed update, Windows Update service |
| `defender` | Antivirus and real-time protection, signature age, tamper protection |
| `firewall` | Every profile enabled and blocking inbound by default |
| `accounts` | Guest and built-in Administrator, accounts without passwords, local admins, auto-logon with stored password |
| `passwords` | Minimum length, lockout threshold |
| `uac` | UAC on, admin consent prompt, secure desktop |
| `bitlocker` | System drive protection |
| `smb` | SMBv1, signing required |
| `rdp` | Remote Desktop with Network Level Authentication |
| `credentials` | LSA protection, LM/NTLMv1, stored LM hashes, WDigest |
| `powershell` | Script block logging, PowerShell 2.0 |
| `secureboot` | Secure Boot |
| `network` | Risky ports (SMB, RDP, WinRM, Telnet…) listening on all interfaces |

Options: `-Check`, `-Json`, `-Output`, `-History`, `-AcceptFile`, `-Quiet`,
`-Strict`, `-List`. Exit codes match the Linux edition (1 on FAIL, or on WARN
with `-Strict`). Not yet in the Windows edition: HTML/TXT/SARIF reports, CVE
and container modules, notifications, `--remote`.

---

## How Anzen compares

| Tool | Scope | How Anzen differs |
|------|-------|-------------------|
| [Lynis](https://github.com/CISOfy/lynis) | Mature host hardening audit (Bash, GPL-3.0) with a hardening index | Lynis has far more checks and distro coverage. Anzen adds container image CVEs and freshness, history and a dashboard, alerts on new findings, expiring accepted risks, fleet over SSH, and a Windows edition |
| [docker-bench-security](https://github.com/docker/docker-bench-security) | CIS Docker benchmark | Anzen covers the Docker daemon and containers as one part of a host audit |
| [Trivy](https://github.com/aquasecurity/trivy) / Grype | Vulnerability scanners | Anzen uses Trivy for its `cve` module and adds the host hardening context |
| OpenSCAP, CIS-CAT | Formal compliance profiles | Anzen is lighter and opinionated, not a compliance attestation |
| linPEAS | Privilege-escalation enumeration (offensive) | Anzen is defensive and explains fixes |

Use Anzen when you want one self-hosted tool for a homelab or small fleet:
hardening, containers and CVEs in one report, trends over time, and a ping only
when something new breaks.

---

## Remote Auditing

Anzen copies itself to each host over SSH, runs there and removes itself — no
installation needed. Give one host or a comma-separated fleet:

```bash
./anzen.sh --remote=admin@10.0.0.5 --html --output=/tmp/remote.html
./anzen.sh --remote=root@pve,root@nas,admin@web1 --parallel
```

- Requires key-based SSH (`BatchMode`); use `root@` or a user with passwordless sudo.
- Only scan settings travel: thresholds, excludes, CVE/image options and your
  accept file. History, notification and dashboard settings stay local.
- With `HISTORY_DIR` set, each host's run is stored under `HISTORY_DIR/<host>/`
  locally — regression alerts are per host, and the dashboard shows the fleet.
- Requested reports (`--html`, `--txt`, `--json`, `--sarif`) come back to
  `--output` (one host) or `reports/anzen_<host>_<timestamp>.<ext>`.
- Pass-through flags: `--check`, `--parallel`, `--strict`, `--quiet`,
  `--no-color`, `--target`, `--wan`, `--resolve-to`.
- Exit code is the worst across hosts; 255 means a host could not be reached.

Schedule a fleet next to the local audit — each keeps its own cron line:

```bash
sudo ./anzen.sh --config=/etc/anzen/anzen.conf --remote=root@pve,root@nas --schedule=weekly:05:30
```

---

## Scheduling

Install a cron job to run Anzen automatically:

```bash
# Via CLI
sudo ./anzen.sh --schedule=daily          # 06:00 every day
sudo ./anzen.sh --schedule=weekly:04:30   # Mondays 04:30
sudo ./anzen.sh --schedule=monthly        # 06:00 on the 1st

# Unattended setup: config, parallel modules, and a separate fleet entry
sudo ./anzen.sh --config=/etc/anzen/anzen.conf --parallel --schedule=weekly:04:30
sudo ./anzen.sh --config=/etc/anzen/anzen.conf --remote=root@pve,root@nas --schedule=weekly:05:30

# Via TUI: Advanced → Install cron schedule
```

The cron job runs `--quiet --txt --json` (plus `--config=`, `--history=`,
`--parallel` and `--remote=` when given) and pipes output to `logger -t anzen`.
Each entry is tagged `# anzen:local` or `# anzen:<hosts>`: re-scheduling
replaces only the entry with the same target. Combine with `HISTORY_DIR`,
`NOTIFY_ON=regression` and `HEARTBEAT_URL` (see
[History & Dashboard](#history--dashboard)) for alerts on new problems and on
runs that stop happening.

---

## CI/CD Integration

```bash
# GitHub Actions / GitLab CI
- name: Security audit
  run: sudo ./anzen.sh --quiet --json --output=audit.json
  # exits 1 on FAIL, 0 on clean

# Diff against baseline to catch regressions only
- run: sudo ./anzen.sh --quiet --diff
  # exits 2 on regression, 0 if no new issues
```

Upload `audit.json` as a build artifact for dashboard ingestion or SIEM forwarding,
or upload SARIF to code scanning (`--sarif`; each result carries a stable
`partialFingerprints.anzenFindingId/v1`).

### Developing anzen

`make ci` runs shellcheck and the bats suite. The repository's own workflow,
`.gitea/workflows/ci.yml`, does the same on every push in Gitea Actions (the
syntax is GitHub Actions compatible) — it only needs git, tar and docker on the
runner, streaming the checkout into pinned shellcheck and bats containers.
