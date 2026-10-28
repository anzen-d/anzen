# Usage


## Quick Start

```bash
# Full audit — terminal output only
sudo ./anzen.sh

# Full audit + HTML report
sudo ./anzen.sh --html

# Interactive TUI
./anzen-tui.sh
```

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
| `--output=FILE` | Override output path; with several formats the extension is swapped per format (`out.html`, `out.json`, …) |
| `--remediate` | Generate `reports/remediate_TIMESTAMP.sh` from findings |

### Filtering

| Flag | Description |
|------|-------------|
| `--check=MODULE` | Run only the specified module — repeatable |
| `--quiet`, `-q` | Suppress `INFO` lines (show `FAIL`/`WARN`/`OK` only) |
| `--no-color` | Disable ANSI colour output (also off when `NO_COLOR` is set or output is not a terminal) |

### Advanced

| Flag | Description |
|------|-------------|
| `--parallel`, `-p` | Run all modules in parallel |
| `--debug` | Trace every command, with file and line, to `reports/anzen_debug_TIMESTAMP.log` (or a `/tmp` file if `reports/` is not writable). The log is mode `600` and can contain secrets the checks matched, so do not share it unreviewed |
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
  安全  Anzen 0.9.0 — Linux Security Audit

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

## Run time

The summary lists the slowest modules (10 seconds or more), and the JSON report
has a `durations` object with every module's run time in seconds. A slow
`files` or `secrets` module usually means a large data tree: exclude it with
`EXCLUDE_PATHS` in `anzen.conf`.

## Severity Levels

| Level | Meaning | Exit impact |
|-------|---------|-------------|
| `FAIL` | Security issue that should be fixed | Triggers exit code `1` |
| `WARN` | Potential risk or deviation from hardening best practice | Exit `1` only with `--strict` |
| `OK` | Check passed | — |
| `INFO` | Informational only — suppressed by `--quiet`. Also used for [accepted risks](reports.md#accepted-risks) | — |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit complete — no `FAIL` findings |
| `1` | One or more `FAIL` findings detected |
| `2` | Baseline diff detected regressions (`--diff` mode) |
| `255` | `--remote`: a host could not be reached or produced no report (worst code across hosts wins otherwise) |

With `--strict`, any `WARN` also exits `1`.

---

[← Back to README](../README.md)
