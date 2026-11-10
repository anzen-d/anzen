# macOS edition

`macos/anzen-macos.sh` audits Macs. It runs with the Bash 3.2 that ships with
macOS, so there's nothing to install, and it uses the same finding IDs, scores,
accept-file format and JSON report as the Linux and Windows editions. Macs
therefore appear in the same history and dashboard.

```bash
git clone https://github.com/anzen-d/anzen.git && cd anzen
sudo ./macos/anzen-macos.sh                    # audit this Mac
sudo ./macos/anzen-macos.sh --json             # + reports/anzen_<timestamp>.json
sudo ./macos/anzen-macos.sh --html --sarif --output=/tmp/mac.json   # /tmp/mac.html, /tmp/mac.sarif.json
sudo ./macos/anzen-macos.sh --history=/Volumes/share/anzen/history   # shared HISTORY_DIR for the dashboard
./macos/anzen-macos.sh --check=filevault --check=firewall
./macos/anzen-macos.sh --list                  # modules
```

Root gives complete results. Without it the script still runs and says which
checks were limited.

| Module | Checks |
|--------|--------|
| `system` | macOS version, days since the last restart (installed updates waiting), disk usage of the Data volume (the sealed system volume `/` is skipped) |
| `inventory` | INFO only: model, serial, CPU, memory, number of applications |
| `updates` | Automatic update settings; security responses / XProtect data (`CriticalUpdateInstall`, `ConfigDataInstall`) disabled is a FAIL; pending recommended updates |
| `xprotect` | XProtect version, and a WARN when its definitions are more than 60 days old |
| `filevault` | Disk encryption |
| `sip` | System Integrity Protection |
| `gatekeeper` | App assessment |
| `firewall` | Application firewall and stealth mode |
| `sharing` | Remote Login, Screen Sharing / Remote Management, File Sharing (SMB/AFP), Printer Sharing listening on all interfaces |
| `accounts` | Automatic login and a stored `/etc/kcpassword`, guest account, number of administrators, password after screen saver |
| `screenlock` | Per user (every local account as root, yourself otherwise): screen lock off or a password delay above 5 minutes (`sysadminctl -screenLock status`, macOS 13+), and no screen saver or display sleep within 30 minutes (managed profile, `-currentHost` screen saver `idleTime`, `pmset` `displaysleep`) |
| `ssh` | `PermitRootLogin` and password authentication, when Remote Login is on |
| `launchd` | Launch daemons and agents: plist or program writable by non-root users (FAIL: runs as root or as every user), unsigned programs (WARN, common malware persistence). Covers `/Library/LaunchDaemons`, `/Library/LaunchAgents` and every user's `~/Library/LaunchAgents` |
| `extensions` | Third-party kernel extensions loaded (WARN), active system extensions (INFO) |
| `profiles` | Inventory: MDM enrollment, configuration profiles (as root), Find My Mac, Lockdown Mode |
| `truststore` | [Distrusted CA certificates](modules.md#trust-stores) (same list as Linux and Windows). **Keychains:** Apple blocks the compromised chain in TLS trust evaluation (Safari, `URLSession`, `nscurl`) while the root stays in `SystemRootCertificates.keychain`. No local command shows that block (`security verify-cert` still reports the root as trusted), so a match there is INFO. A listed certificate that someone added to the System or login keychain is a FAIL. **`/etc/ssl/cert.pem`**, used by `curl`, `git` and `openssl`, does not get Apple's block, so a listed root there is a FAIL. The same goes for Homebrew's bundles, Python `certifi` and Java `cacerts` |

Options: `--check=MODULE`, `--json`, `--html`, `--txt`, `--sarif`, `--csv`, `--output=FILE`, `--history=DIR`,
`--accept=FILE`, `--quiet`, `--no-color`, `--strict`, `--list`, `--version`.
Exit codes match the other editions: 1 on FAIL, or on WARN with `--strict`.
With several formats `--output` swaps the extension, as in `anzen.sh`. The
HTML, TXT and SARIF reports come from the Linux edition's generators.

**Fleet.** `anzen.sh --remote=admin@mac1,root@web1` audits Macs and Linux hosts
in one run: anzen detects macOS (`uname -s`) and runs this edition there, as
root when the login has passwordless `sudo`. Reports, history, notifications
and the dashboard stay on the Linux machine. See [fleet audits](fleet.md).

**How it is tested.** CI runs the tests against stub macOS commands under a
real Bash 3.2. On a `macos-latest` runner it then checks that finding IDs
match the Linux edition for a corpus of real messages, and does a full run as
root.

Not yet in the macOS edition: notifications when run on its own (use the
Linux fleet for alerts), CVE and container checks. See the [roadmap](../ROADMAP.md).

---

[← Back to README](../README.md)
