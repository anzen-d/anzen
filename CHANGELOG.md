# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.11.1] - 2026-10-28

Fixes from the first run on a real Mac (macOS 26.6).

### Fixed
- **macOS trust stores: false FAIL for certificates Apple already blocks.** Apple
  distrusts CAs through automatic certificate configuration data updates while
  the certificate stays in `SystemRootCertificates.keychain`. Keychain matches
  are now checked with macOS's own trust evaluation (`security verify-cert`):
  blocked is OK, still trusted is FAIL. AAA Certificate Services in a keychain
  is INFO (Apple blocks the cross-signed intermediates instead)
- **macOS uptime showed ~20,000 days**: `kern.boottime` was parsed from the
  `usec` field instead of `sec`
- macOS disk check no longer reports the sealed, read-only system volume `/`
  next to the Data volume that actually fills up

### Added
- **macOS: `/etc/ssl/cert.pem` and Homebrew CA bundles** are checked. `curl`,
  `git` and `openssl` use them without Apple's block, which made this the real
  remaining exposure on up-to-date Macs. A listed root there is a FAIL, with
  Apple's interim remedy

## [0.11.0] - 2026-10-28

### Added
- **macOS edition** — `macos/anzen-macos.sh`, runs with the Bash 3.2 that ships
  with macOS. 10 modules: system, updates, FileVault, SIP, Gatekeeper,
  application firewall and stealth mode, sharing services, accounts
  (auto-login, guest, admins), SSH and trust stores (keychains, certifi, Java;
  the shared distrusted-certificate list). Same finding IDs, scores, accept
  file, JSON and history layout as the other editions
- CI: macOS tests under a real Bash 3.2 with stub macOS commands, plus a
  `macos-latest` job that checks finding-ID parity with the Linux edition
  (BSD sed) on a 141-message corpus and does a full run as root

## [0.10.0] - 2026-10-28

### Added
- **`truststore` module (Linux and Windows): distrusted CA certificates.**
  Checks system CA bundles, local anchors, Java `cacerts`, Python `certifi` and
  the CA bundle of every running container against
  `lib/data/distrusted-certs.tsv`, matching by SHA-256 certificate fingerprint
  (no OpenSSL needed; identical bundles are fingerprinted once). The Windows
  edition checks the machine/user stores and treats certificates in the
  Disallowed store as blocked
- First entries: the eMudhra incident of October 2026. FAIL for the 16
  compromised intermediate certificates (8 keys, eMudhra- and Sectigo-issued)
  and the three emSign G3 roots, WARN for Sectigo *AAA Certificate Services*,
  through which the cross-signed intermediates chain. Fingerprints were computed
  from the certificates in the researcher's disclosure, and the roots were
  cross-checked against an independent source
- `DISTRUSTED_CERTS_FILE` for site-specific entries, `TRUSTSTORE_SCAN_CONTAINERS`

## [0.9.1] - 2026-10-28

### Changed
- **License: MIT → GNU AGPL-3.0-or-later.** Using Anzen stays free with no
  obligations; distributing a modified version or offering it as a network
  service requires sharing the changes under the same license. Version 0.9.0
  remains available under MIT
- Contributions use the Developer Certificate of Origin (`git commit -s`)
  instead of a CLA; CI checks the sign-off on pull requests
- SPDX license headers in all source files
- The name and logo are covered by a trademark note ([TRADEMARKS.md](TRADEMARKS.md))
- Dashboard: "New FAILs", "Fixed" and "Accepted risks expiring" now cover the whole fleet, each entry tagged with its host; the view opens on the lowest-scoring host
- Live demo data tells a story (a new FAIL, a fix, an expiring accepted risk) and accepted-risk dates move with the demo dates

### Added
- [ROADMAP.md](ROADMAP.md) with good first contributions and bigger features


## [0.9.0] - 2026-10-27

First public release.

### Linux edition (`anzen.sh`)
- 22 check modules: system, users and sudo, SSH, network and firewall, kernel
  sysctls, kernel modules, file permissions, SUID/SGID, world-writable files,
  secrets, systemd sandboxing, TLS certificates, compilers, PATH safety,
  services, logins and cron, auditd and time sync, container runtimes
  (Docker, Podman, nerdctl, LXD, LXC, Kubernetes), container image freshness,
  CVEs in host packages and running images (via Trivy), and local/external pentest
- Runs on Debian, Ubuntu, Fedora, Rocky/RHEL, Alpine, Arch and openSUSE;
  no runtime dependencies beyond Bash 4.2+ and standard tools
- Stable finding IDs, per-section scores, accepted risks with expiry dates,
  baseline diffs, a generated remediation script
- HTML, TXT, JSON and SARIF reports
- Run history with a static multi-host dashboard, alerts only on new FAILs
  (ntfy or any command) and a heartbeat URL for dead-man monitoring
- Fleet mode: `--remote=host1,host2` audits hosts over SSH without installing anything
- Interactive TUI, cron scheduling, custom check modules, bash/zsh completions

### Windows edition (`windows/anzen.ps1`)
- 14 modules for Windows PowerShell 5.1+ / PowerShell 7: Defender, firewall,
  updates, accounts, password policy, UAC, BitLocker, SMB, RDP, credential
  protection, PowerShell logging, Secure Boot, listening ports and system state
- Same finding IDs, scores, accept file and JSON layout as the Linux edition,
  so both appear in one dashboard

### Project
- MIT license, contributing guide, security policy, issue and PR templates
- CI on every push: shellcheck, 129 bats tests, the distro matrix, and
  PSScriptAnalyzer, Pester and a real run on Windows

<details>
<summary>Pre-release development history (0.1.0 – 0.8.1)</summary>

### [0.8.1] - 2026-10-27

#### Fixed
- **World-readable `/etc/shadow` was only a WARN**: file permission checks now FAIL when a file grants access to everyone or extra write access, WARN for extra group read/execute, and accept stricter-than-expected modes (RHEL's `/etc/shadow` is `000`)
- Kernel checks read `/proc/sys` when the `sysctl` binary is missing (minimal images reported every parameter as "not available"); an unreadable `fs.suid_dumpable` is INFO, not a WARN with an empty value
- Summary table column widened so long section names stay aligned
- `install.sh` is executable in the repository, so `sudo ./install.sh` works as documented
- Dockerfile no longer suggests auditing the host by mounting `/` — anzen audits the system it runs on; the image is a runner for `--remote`

#### Changed
- README rewritten for first-time users: logo, demo animation, quick start for Linux/Windows/remote, common workflows; the full reference moved to `docs/` (installation, usage, modules, reports, configuration, fleet, windows)
- GitHub CI: `actions/checkout@v5`; the Windows job accepts exit 1 (findings) from the real run; distro-matrix failures appear as annotations

### [0.8.0] - 2026-10-27

#### Added
- MIT license, `CONTRIBUTING.md`, `SECURITY.md`, GitHub issue/PR templates and a GitHub Actions workflow (Linux lint+tests, distro matrix, Windows PSScriptAnalyzer + Pester + a real run on Windows PowerShell 5.1)
- README: overview with dashboard screenshot, responsible-use note, comparison with Lynis/docker-bench/Trivy/OpenSCAP/linPEAS
- **Windows edition** — `windows/anzen.ps1` (Windows PowerShell 5.1+ / PowerShell 7): 14 modules (system, updates, defender, firewall, accounts, passwords, uac, bitlocker, smb, rdp, credentials, powershell, secureboot, network). Same finding-ID algorithm (IDs match the Linux edition byte for byte), scores, accept file and JSON layout, so `-History` runs appear in the same dashboard and regression logic as Linux hosts
- Pester tests (`windows/tests`) and PSScriptAnalyzer in CI via the `mcr.microsoft.com/powershell` image

### [0.7.3] - 2026-10-27

#### Added
- **Distro matrix** (`tests/distro-matrix.sh`, `make matrix`, CI): runs every passive module in Debian 12, Ubuntu 24.04, Fedora 41, Rocky 9, Alpine 3.20, Arch and openSUSE Leap 15.6 containers and fails on shell errors (missing commands, bad arithmetic, unbound variables). Images come from quay.io / AWS / openSUSE mirrors, not Docker Hub

#### Fixed
- `grep -c … || echo 0` printed "0" twice when nothing matched (grep -c already prints 0), breaking arithmetic in network, logins, packages, auditd and system checks
- Remaining bare `sudo` calls (nft, iptables, apk, lastb, auditctl) go through `_priv`
- No `hostname`/`uptime` binaries in minimal images (Fedora, Arch, Debian containers): `_hostname` falls back to `uname -n`; uptime and load come from `/proc`

### [0.7.2] - 2026-10-27

#### Fixed
- **cve: host findings did not say which binary ships a vulnerable library** ("stdlib v1.13.3 in host"): non-OS targets are named — `stdlib v1.23.4 in host /usr/local/bin/terraform`, `undici 6.28.0 in <image> Node.js`
- **Repeated-findings summary split on any `:`**, so versions (`1:2.66`) and ports (`:8080 — …`) produced junk groups; it now groups on `": "` and ignores messages without one
- **`make lint` could never fail** (output piped through `grep … || true`) and skipped `anzen-tui.sh`/`install.sh`; it now lints the same files as CI and fails on warnings
- Docker image lacked `curl` (notifications, heartbeat, `images` upstream check)
- README: requirements (curl, trivy, docker/podman, ssh), exit code 255 and `--strict`, `images`/notify config keys, scheduling with tagged entries, SARIF fingerprints, CI workflow; TUI banner version

### [0.7.1] - 2026-10-27

#### Changed
- **images: upstream check no longer spends Docker Hub pulls**: `docker buildx imagetools inspect` issues manifest GETs, which Docker Hub counts as pulls (77 per run exhausted the anonymous limit and broke an unrelated CI job). It now sends registry HEAD requests with anonymous bearer tokens via curl — free on Docker Hub, works for ghcr.io/lscr.io/private registries, and no longer needs buildx

### [0.7.0] - 2026-10-27

#### Added
- **Fleet mode — `--remote=host1,host2,...`**: audits each host over SSH (anzen copies itself, runs, removes itself) and stores every host's JSON report in the local `HISTORY_DIR/<host>/`, so regression alerts are per host and the dashboard shows the fleet. Only scan settings and the accept file are shipped; history, notify and dashboard config stay local. Requested report formats are fetched back. Exit code is the worst across hosts (255 = unreachable). `ANZEN_SSH` overrides the ssh binary
- `--schedule` tags each cron entry (`# anzen:local`, `# anzen:<hosts>`), so a fleet schedule no longer replaces the local one
- **`images` module — container image freshness**: per running image, WARN when it is older than `IMAGE_MAX_AGE_DAYS` (180), uses `:latest` or no tag (`IMAGE_WARN_LATEST`), its containers still run an older image after a newer one was pulled, or the registry has a newer digest (`IMAGE_CHECK_UPDATES`: registry HEAD requests with anonymous tokens via curl, so Docker Hub does not count them as pulls)
- **CI**: `.gitea/workflows/ci.yml` runs shellcheck and the bats suite on every push and pull request; portable (git + tar + docker on the runner, no host paths)
- **`cve` module — known vulnerabilities via trivy**: scans the host root filesystem (OS packages plus installed language packages: jars, node_modules, wheels, Go binaries…) and every running Docker/Podman image, one scan per image. One finding per vulnerable package version: CRITICAL → FAIL, HIGH → WARN, with counts, up to three CVE IDs, the fixed version and the containers using the image. Stable IDs, so `NOTIFY_ON=regression` alerts on newly published CVEs and accepted risks can expire
- Config: `CVE_SEVERITY` (default `CRITICAL,HIGH`), `CVE_IGNORE_UNFIXED` (default `true`: only CVEs with a fix), `CVE_SCAN_IMAGES` (default `true`), `CVE_TIMEOUT` (default `60m`), `CVE_SKIP_DIRS`
- A failed trivy run is reported as WARN instead of looking like a clean result

#### Changed
- `--remote` replaces the single-host remote mode: arguments are no longer passed through blindly (a local `--config=`/`--history=` path made no sense remotely); local-only settings stay local
- Notification policy (`NOTIFY_ON`) and the heartbeat moved into `notify.sh` (`notify_run`, `heartbeat`) and are shared by local and fleet runs
- `history_save` no longer mangles history paths containing `-` when two runs land in the same second
- The packages module no longer runs trivy (moved to `cve`); debsecan stays its fallback when trivy is absent

### [0.6.3] - 2026-10-27

#### Fixed
- **Files check walked excluded trees**: `/var/lib/docker`, `/proc`, `EXCLUDE_PATHS` etc. were filtered with `! -path`, so `find` still descended into them (100k+ Docker layer files). `dir/*` excludes are now pruned; the SUID scan uses the same pruned walk. ~7 min → ~2.5 min on a busy Docker host

### [0.6.2] - 2026-10-22

#### Fixed
- **Secrets scan took 10+ minutes** on a host with 247k locked certbot keys and large dependency trees: key files are now filtered by permission first (only group-writable or world-accessible ones are read), found in a single `find` walk with batched `grep`, and `node_modules`, `vendor`, `testdata`, `fixtures`, `site-packages`, `.cache` and Go module caches are pruned. `-xdev` keeps the scans off NFS/media mounts below `/home`. ~10 min → ~90 s
- **Test-fixture keys reported as exposed** (Go module cache, `node_modules`, vendored test suites)

#### Changed
- A private key is "loose" when group-writable or accessible by others; group read (e.g. Debian's `ssl-cert` group on `/etc/ssl/private`) is accepted

### [0.6.1] - 2026-10-22

False positives found by the first real fleet run (134 FAIL → mostly noise):

#### Fixed
- **Local pentest flagged every path of single-page apps** (`/.env`, `/db.sql`, `/wp-admin`… all "exposed" because the app answers 200 for any URL): it now uses the same canary baseline and secret scan as `pentest_external`. A 200 is FAIL only when the body contains secrets, WARN when it differs from the catch-all, skipped otherwise. Shared helpers moved to `lib/http_probe.sh`
- **Certificates reported as private keys**: `*.pem`/`*.key` count as keys only when they contain a `PRIVATE KEY` block
- **`/bin` and `/sbin` reported as world-writable PATH dirs** on usr-merged systems: permissions are read from the symlink target
- **One NAS volume reported once per NFS export / bind mount**: disk usage is listed once per volume
- **Any app on 9200/5984 reported as Elasticsearch/CouchDB**: the port is FAIL only when the HTTP(S) response looks like that datastore (or nothing answers), otherwise WARN
- **HTTP status lines reported as version disclosure** (`HTTP/1.1 400 Bad Request`)
- Two history runs in the same second no longer overwrite each other

#### Changed
- Local pentest: an open, non-high-risk port is INFO instead of WARN (95 WARNs on a busy Docker host); the probes that follow report actual weaknesses

### [0.6.0] - 2026-10-21

#### Added
- **Run history** (`--history=DIR` or `HISTORY_DIR`): every run is saved as a JSON report to `DIR/<host>/<UTC timestamp>.json`; the newest `HISTORY_KEEP` (default 52) are kept. Several hosts can share one dir
- **Static dashboard** (`--dashboard=FILE`, or `DASHBOARD_FILE` to rebuild after every saved run): one self-contained HTML file, no network access — per-host score cards with change and stale warning, score trend, new/fixed FAILs since the previous run, accepted risks expiring within 30 days, section table, filterable findings; light/dark
- **`NOTIFY_ON=always|fail|regression`**: `regression` notifies only when a FAIL ID was not a FAIL in the previous history run (never on a host's first run); ntfy messages list the new FAILs. `NOTIFY_CMD` gets `ANZEN_NEW_FAILS` and `ANZEN_NEW_FAIL_LIST`. `NOTIFY_ON_FAIL_ONLY=true` still works (= `fail`)
- **`NOTIFY_NTFY_TOKEN`**: bearer token for access-controlled ntfy topics
- **`HEARTBEAT_URL`**: fetched after every run, a dead-man switch for Uptime Kuma push monitors, healthchecks.io and similar
- **`CUSTOM_CHECKS_DIR`**: site-specific modules outside the anzen tree (`<name>.sh` defining `run_<name>_check`), usable with `--check=<name>`; each file must pass the `anzen.conf` ownership/world-writable check
- JSON reports carry `version`

#### Changed
- `--schedule` keeps `--config=`, `--history=` and `--parallel` in the installed cron command
- Unknown `--check=` names are validated after custom checks load
- Reports, Dockerfile and README no longer reference a private repository URL; report footers show the anzen version

### [0.5.0] - 2026-10-21

#### Added
- **Stable finding IDs** (`<section-slug>-<8 hex>`): hash of section + message with volatile parts (percentages, sizes, durations, counts) normalised, so `Disk / at 81%` and `Disk / at 93%` keep one ID. Shown in TXT (`ID:` line), HTML (under each finding), JSON (`id`) and SARIF (`partialFingerprints.anzenFindingId/v1`)
- **Accepted risks** (`ACCEPT_FILE`, default `anzen.accept`; see `anzen.accept.example`): `ID YYYY-MM-DD reason` per line. Matching WARN/FAIL findings are reported as INFO with the reason until the date passes, then return at their real level marked "acceptance expired". The file gets the same ownership/world-writable check as `anzen.conf`
- **Per-section scores** in the terminal summary, TXT, HTML section badges and JSON `sections[]`
- **Repeated findings** in the terminal summary: WARN/FAIL messages sharing a prefix (text before `:`) 3+ times are listed once with a count

#### Changed
- **Overall score is the mean of section scores** instead of `100 - FAIL*10 - WARN*3` across the host, so one noisy section (e.g. 150 container warnings) no longer pins the whole host at 0%
- **`--diff` compares finding IDs**, not message text: a FAIL whose numbers change is no longer reported as one regression plus one fix. Baselines saved by older versions are compared by message with a notice to re-run `--baseline`
- Baseline file stores `{"id", "message"}` objects; parsing no longer uses python3
- Findings TSV gained an ID field: `LEVEL SECTION MESSAGE ID REMEDY`
- `anzen.conf` and `anzen.accept` are gitignored

#### Fixed
- **JSON report took ~45 s for 400 findings** (five `sed` forks per finding); now one `awk` pass, 0.25 s
- **Backslashes in remedies were mangled**: `remedy()` passed the command through `awk -v`, which expands escapes (`\t` became a tab, `\ ` lost its backslash); now passed via `ENVIRON`
- **HTML report expanded backslashes** in messages and remedies (`printf '%b'`)

### [0.4.2] - 2026-10-21

#### Fixed
- **`docker_security` module never ran**: it was missing from `ALL_MODULES`, so `--check=docker_security` (and the TUI entry) silently did nothing; the container runtime checks in `lib/checks/runtimes/` now run
- **Stale version string**: `ANZEN_VERSION` reported 0.3.0 since 0.4.0
- **`--output=` with several formats**: only the first format honoured it; now each format gets the path with its own extension (`out.html`, `out.txt`, `out.json`, `out.sarif.json`)
- **Baseline diff without python3**: the grep fallback parsed the `date` value as a FAIL (always shown as "resolved") and broke on messages containing quotes
- `--help` said `--diff` exits 1 on regression; it exits 2
- **Privileged checks could hang or silently return nothing**: `sudo` calls in checks prompted for a password (blocking cron and `--parallel` runs) and failed outright as root without sudo (e.g. the Docker image). New `_priv` helper in `lib/utils.sh` runs directly as root, via `sudo -n` when passwordless sudo works, unprivileged otherwise; `sudo -l` is now `sudo -n -l`
- `_ssh_val` moved to file scope so it can be unit-tested

#### Changed
- Unknown `--check=` modules are rejected with exit 1 instead of running nothing
- Shell completions list `docker_security`, `pentest`, `pentest_external` and the 0.4.x flags

### [0.4.1] - 2026-05-03

#### Fixed
- **TLS false positive on systems with TLSv1.0 disabled**: `tls.sh` now excludes `(NONE)` cipher from TLSv1.0 detection — client-side OpenSSL refusal was matching the grep and raising false FAILs
- **Secrets scanner false positives**: `secrets.sh` now skips CA bundle paths (`ca-trust`, `ca-certificates`, `cacert*`) and container overlay paths (`docker/overlay2`, `containers/storage/overlay`) in both the loose-permissions and world-readable checks
- **Disk reporting false positives**: `system.sh` now excludes `overlay` filesystem type from disk usage reporting, preventing Docker container layers from appearing as separate disk entries

### [0.4.0] - 2026-05-03

#### Added
- **SARIF 2.1.0 output** (`--sarif`): machine-readable report compatible with GitHub/GitLab code scanning
- **`--strict` flag**: exits non-zero on WARN in addition to FAIL — useful for CI gates
- **Cron time customization**: `--schedule=daily:HH:MM` (e.g. `--schedule=daily:02:30`); defaults to 06:00 if no time given
- **`FAIL_AS_WARN` config option**: space-separated substrings — matching FAIL findings are downgraded to WARN for accepted-risk items
- **Notification hook**: post-audit push notification via `NOTIFY_NTFY_URL` (ntfy) or generic `NOTIFY_CMD`; `NOTIFY_ON_FAIL_ONLY=true` to suppress clean-run noise
- **CVE scanning in packages module**: uses `trivy` if present (CRITICAL→FAIL, HIGH→WARN); falls back to `debsecan` on Debian; info message if neither available
- **`make ci` target**: runs lint then test in sequence for use in CI pipelines
- **`lib/utils.sh`**: shared utility module; `_safe_source_config` extracted here for independent testability
- **3 new BATS tests** for `_safe_source_config`: valid config, world-writable rejection, non-existent file

#### Fixed
- **Shell injection in remote mode**: all variables embedded in remote SSH commands now go through `printf '%q'`; each arg in `REMOTE_ARGS` is shell-quoted at rebuild time
- **Unsafe config sourcing**: `_safe_source_config()` validates file ownership (must be current user or root) and rejects world-writable configs before sourcing
- **World-readable temp files**: both `mktemp` calls now run inside `(umask 077; mktemp ...)` ensuring 0600 permissions regardless of process umask
- **Unvalidated `--remote=` input**: host string validated against `^([a-zA-Z0-9._-]+@)?[a-zA-Z0-9._-]+$`; returned tmpdir path validated before use in any remote command
- **Silent check module load failures**: each `lib/checks/*.sh` is syntax-checked with `bash -n` before sourcing; missing `run_*_check` functions are reported after load
- **Baseline symlink attack**: `save_baseline()` rejects symlinks in both the output path and its parent directory
- **TSV field corruption**: `_record()` strips embedded tabs and newlines from finding messages before writing

### [0.3.0] - 2026-03-27

#### Added
- **7 new check modules**:
  - `secrets` — private key permissions, .env files, AWS credentials, .netrc, hardcoded secrets in configs
  - `network2` — promiscuous NICs, IPv6 privacy, IP forwarding, source routing, SYN cookies, rp_filter
  - `systemd_hardening` — per-service NoNewPrivileges/PrivateTmp/ProtectSystem/ProtectHome scoring
  - `tls` — TLS certificate expiry from files and live ports, TLSv1.0 detection
  - `compiler` — compiler/build tool detection, offensive tools (nmap, metasploit, hydra), packet capture
  - `path_check` — world-writable PATH dirs, LD_PRELOAD/LD_LIBRARY_PATH, /etc/ld.so.preload
  - `modules` — risky kernel module detection, blacklist checking, kexec_load_disabled
- **Remediation system**: `remedy()` function appends fix commands to findings; `--remediate` generates `remediate_TIMESTAMP.sh`
- **Baseline & diff mode**: `--baseline` saves JSON snapshot; `--diff` compares and exits 1 on regressions
- **Configurable thresholds**: `lib/config.sh` with `anzen.conf` override support
- **Weighted scoring**: penalty-based (100 - FAILs×10 - WARNs×3), clamped to 0
- **Parallel execution**: `--parallel` / `-p` runs all modules concurrently, merges output in order
- **Remote mode**: `--remote=user@host` tarballs anzen to remote, runs, cleans up
- **Scheduling**: `--schedule=daily|weekly|monthly` installs crontab entry
- **HTML improvements**: dark/light theme toggle, filter by severity, print stylesheet, inline remedy copy-to-clipboard
- **DX files**: `anzen.conf.example`, `install.sh`, `completions/anzen.bash`, `completions/anzen.zsh`, `Dockerfile`
- Flags: `--version`, `--no-color`, `--config=FILE`, `--output=FILE`

#### Changed
- Findings file format changed to tab-separated (`LEVEL\tSECTION\tMESSAGE\tREMEDY`) for reliable field splitting
- All existing modules updated with `remedy()` calls
- HTML report fully rewritten with CSS variable theming and JS filtering
- JSON and TXT reports include remedy field per finding
- Exit codes: 0=clean, 1=FAILs found, 2=diff regressions

### [0.2.0] - 2026-03-26

#### Added
- HTML report generation (`--html`)
- JSON report generation (`--json`)
- Plain-text report generation (`--txt`)
- OS family detection (debian/rhel/arch/alpine/suse)
- 10 check modules: system, users, ssh, network, packages, files, services, logins, kernel, auditd
- Weighted security score summary

### [0.1.0] - 2026-03-25

#### Added
- Initial project scaffolding
- Basic security checks: SSH, users, system resources, packages, network
- Terminal output with colored FAIL/WARN/OK/INFO levels

</details>
