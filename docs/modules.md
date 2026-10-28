# Check modules


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
| Trust stores | `truststore` | Distrusted / compromised CA certificates in system bundles, Java `cacerts`, Python `certifi`, local anchors and running containers |
| Vulnerabilities | `cve` | Known CVEs in host packages and running container images (needs trivy) |
| Local Pentest | `pentest` | Active self-pentest: port scan, service banner grabbing, local HTTP sensitive path enumeration, HTTP security headers |
| External Pentest | `pentest_external` | Active pentest of a remote endpoint (requires `--target`): DNS recon, port scan with service fingerprinting, TLS/SSL analysis, HTTP security headers, content-aware sensitive path enumeration, CORS, HTTP methods, open redirect, clickjacking, information disclosure |


## Trust stores

The `truststore` module looks for CA certificates that must no longer be
trusted, such as compromised keys or distrusted CAs, everywhere a host keeps CA
certificates:

- the system bundle (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/…`)
- locally added anchors (`/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`)
- Java `cacerts` (when `keytool` is installed) and Python `certifi`
- the CA bundle **inside every running container**, because a patched host
  does not fix an image built before the patch

Certificates are matched by the SHA-256 fingerprint of the certificate itself,
listed in [`lib/data/distrusted-certs.tsv`](../lib/data/distrusted-certs.tsv).
The fingerprints are computed with `base64` and `sha256sum`, so OpenSSL is not
needed. The Windows edition checks the machine and user certificate stores
against the same list, and a certificate in the **Disallowed** store counts as
blocked.

**First entries: eMudhra, October 2026.** Eight eMudhra intermediate CAs (six
for TLS, two for code signing) had private keys that could be recovered, and
each was also cross-signed by Sectigo's *AAA Certificate Services* root.
Browsers blocked them within hours, but anything relying on an older CA
bundle (outdated `ca-certificates`, old container images, Java or Python
bundles) could still trust certificates issued with those keys. Anzen reports:

- **FAIL** for any of the 16 compromised intermediate certificates (8 keys,
  each with an eMudhra-issued and a Sectigo cross-signed version) and for the
  three emSign G3 roots
- **WARN** for *AAA Certificate Services*, through which the cross-signed
  intermediates chain. Updated bundles no longer include it. Update the
  bundle rather than deleting the root by hand, because that can break other
  legacy Sectigo chains

The fix is to update `ca-certificates` on the host and rebuild or pull fresh
images for the affected containers. On **macOS**, Apple blocks the certificates
through automatic configuration updates and the keychain check reflects that.
The exception is `/etc/ssl/cert.pem`, which `curl`, `git` and `openssl` use
without Apple's block. Apple's interim advice is to remove the listed roots
from that file; a macOS update may restore it. References:
[Mozilla incident](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
[Apple](https://support.apple.com/en-us/149555),
[researcher's disclosure](https://emudhra.we-have-a-problem.com/).

**Adding entries.** Future incidents are added to the bundled list as one line
per certificate. For site-specific distrust, point `DISTRUSTED_CERTS_FILE` to
your own file in the same format:

```
# SHA256  SEVERITY  INCIDENT  NAME  REFERENCE   (tab-separated)
42C4ACCD…1493	FAIL	emudhra-2026	EM DV TLS CA - G3B (…)	https://…
```

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

### Actively exploited CVEs (CISA KEV)

Hundreds of CVEs per host are normal; the few that attackers use right now are
what to fix first. Anzen downloads the [CISA Known Exploited Vulnerabilities
catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(cached for a day) and matches it against every trivy result. A match is a
**FAIL at any severity, with or without a fix**, and is named first:

```
[FAIL] sudo 1.9.5 in host: ACTIVELY EXPLOITED CVE-2025-1111 (CISA KEV, due 2025-04-22, used by ransomware) — 1 MEDIUM
```

The due date is the deadline CISA sets for US federal agencies, a useful
yardstick for everyone else. Without network access the cached list is used;
without any list the check is skipped (INFO), never failed.

CVEs published in the last `CVE_NEW_DAYS` days are listed in one INFO line per
host or image, so a weekly report shows what is new at a glance.

The **Exploited CVEs — fix first** section turns the exploited findings into
an action list:

```
[INFO] Reboot into 6.8.0-147-generic (installed; running 6.8.0-142-generic) — fixes actively exploited kernel CVEs: CVE-2026-53266 CVE-2026-53362
[INFO] old/speedtest:latest [speedtest]: 3 actively exploited CVEs (CVE-2021-40438 CVE-2021-41773 CVE-2021-42013), used by ransomware
[INFO] CVE-2026-111497 (brotli-libs, libbrotli1): 36 targets, 35 with a fix available
```

Targets (the host, or an image with its containers) are ranked with
ransomware-linked ones first, then by the number of exploited CVEs; CVEs that
affect several targets show how far one update reaches.

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
| `CVE_NEW_DAYS` | `7` | CVEs published within this many days are listed as new |
| `KEV_CHECK` | `true` | Match against the CISA KEV catalog |
| `KEV_URL` | CISA feed | KEV JSON feed (a mirror, for air-gapped sites) |
| `KEV_CACHE_DIR` | `/var/cache/anzen` | Where the list is cached (`~/.cache/anzen` without root) |

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

[← Back to README](../README.md)
