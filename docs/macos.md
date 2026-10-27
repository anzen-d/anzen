# macOS edition

`macos/anzen-macos.sh` audits Macs. It runs with the Bash 3.2 that ships with
macOS, so there's nothing to install, and it uses the same finding IDs, scores,
accept-file format and JSON report as the Linux and Windows editions. Macs
therefore appear in the same history and dashboard.

```bash
git clone https://github.com/anzen-d/anzen.git && cd anzen
sudo ./macos/anzen-macos.sh                    # audit this Mac
sudo ./macos/anzen-macos.sh --json             # + reports/anzen_<timestamp>.json
sudo ./macos/anzen-macos.sh --history=/Volumes/share/anzen/history   # shared HISTORY_DIR for the dashboard
./macos/anzen-macos.sh --check=filevault --check=firewall
./macos/anzen-macos.sh --list                  # modules
```

Root gives complete results. Without it the script still runs and says which
checks were limited.

| Module | Checks |
|--------|--------|
| `system` | macOS version, days since the last restart (installed updates waiting), disk usage |
| `updates` | Automatic update settings; security responses / XProtect data (`CriticalUpdateInstall`, `ConfigDataInstall`) disabled is a FAIL; pending recommended updates |
| `filevault` | Disk encryption |
| `sip` | System Integrity Protection |
| `gatekeeper` | App assessment |
| `firewall` | Application firewall and stealth mode |
| `sharing` | Remote Login, Screen Sharing / Remote Management, File Sharing (SMB/AFP), Printer Sharing listening on all interfaces |
| `accounts` | Automatic login and a stored `/etc/kcpassword`, guest account, number of administrators, password after screen saver |
| `ssh` | `PermitRootLogin` and password authentication, when Remote Login is on |
| `truststore` | [Distrusted CA certificates](modules.md#trust-stores) (same list as Linux and Windows) in the System Roots, System and login keychains, Python `certifi` and Java `cacerts` |

Options: `--check=MODULE`, `--json`, `--output=FILE`, `--history=DIR`,
`--accept=FILE`, `--quiet`, `--no-color`, `--strict`, `--list`, `--version`.
Exit codes match the other editions: 1 on FAIL, or on WARN with `--strict`.

**How it is tested.** CI runs the tests against stub macOS commands under a
real Bash 3.2. On a `macos-latest` runner it then checks that finding IDs
match the Linux edition for a corpus of real messages, and does a full run as
root.

Not yet in the macOS edition: HTML/TXT/SARIF reports, notifications,
`--remote`, CVE and container checks. See the [roadmap](../ROADMAP.md).

---

[← Back to README](../README.md)
