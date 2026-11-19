# Fleet audits, scheduling and CI


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

macOS hosts need nothing special: anzen detects them (`uname -s`) and runs
the [macOS edition](macos.md) there, as root when the login has passwordless
`sudo`. Only `--check`, `--strict`, `--quiet` and `--no-color` reach a Mac.

Windows hosts with the OpenSSH server work the same way: anzen sees that there
is no `uname`, asks PowerShell, and runs the [Windows edition](windows.md) in one
SSH session (files go in and reports come back over stdin/stdout, so it works
with `cmd.exe` or PowerShell as the SSH shell). Log in as an administrator for
complete results. Only `--check` (Windows module names) and `--strict` reach a
Windows host. The controller needs `iconv` and `base64`.

```bash
./anzen.sh --remote=root@web1,admin@pc1 --html
```

From a Windows machine you can also use PowerShell remoting instead:
`windows\anzen.ps1 -Remote pc1,pc2 -History <dir>` (see
[Windows edition](windows.md#fleet--remote)). Point `-History` at the Linux
`HISTORY_DIR` (for example an SMB share) and the dashboard shows both.

## Push agents

With `--remote` the controller logs in to every host. A push agent turns that
round: the host runs its own audit and uploads the report. The host needs only
outbound HTTPS, so it works behind NAT, and the controller holds no key for any
host and can never run a command there.

On the controller (needs `python3`, `openssl` and `HISTORY_DIR`):

```bash
# anzen.conf
HISTORY_DIR="/var/lib/anzen/history"
DASHBOARD_FILE="/var/lib/anzen/www/index.html"
AGENT_PUBLIC_URL="https://anzen.example.com"   # how hosts reach the receiver

sudo anzen --config=/etc/anzen/anzen.conf --receiver
```

The receiver speaks plain HTTP on `AGENT_LISTEN` (default `127.0.0.1:8787`).
Put your reverse proxy with TLS in front of it and allow request bodies of a
few megabytes (a large host's report is about 1 MB; the limit is 20 MB). Run it
as the user that owns `HISTORY_DIR`, for example from a systemd unit.

On each host, as root:

```bash
curl -fsSL https://anzen.example.com/enrol | sudo sh
```

This installs the controller's copy of anzen to `/usr/local/lib/anzen`, makes a
key pair in `/etc/anzen/agent`, sends the public key and adds a weekly cron
run. It ends with a code:

```
Enrolment sent to https://anzen.example.com.
  Code: 1a2b-3c4d-5e6f
```

Nothing from that host is accepted until you approve the code on the
controller. Compare it with what the host printed:

```bash
sudo anzen --config=/etc/anzen/anzen.conf --agent-list
sudo anzen --config=/etc/anzen/anzen.conf --agent-approve=1a2b-3c4d-5e6f:web1
```

`web1` is the name of the host's history directory and its name on the
dashboard. The host cannot change it: the hostname inside an uploaded report is
replaced by the approved name. Without `:name` the host's own short hostname is
used, unless history under that name already exists.

From then on every full run on the host (not `--check`, not `--offline`) uploads
its JSON report, signed with the host's key. The controller stores it under
`HISTORY_DIR/web1/`, sends regression alerts (`NOTIFY_ON`) and rebuilds the
dashboard, the same as for `--remote` hosts.

- A host that already has anzen can skip the script: `sudo anzen --enrol=https://anzen.example.com`.
- `--agent-revoke=web1` stops accepting a host; its history stays.
- To leave, on the host: `rm -r /etc/anzen/agent`.
- To update a host's anzen, run the `curl` line again. The key is kept, so no new approval is needed.

### Web controller

The receiver also serves a page for the admin, on its own port
(`AGENT_ADMIN_LISTEN`, default `127.0.0.1:8788`; set it empty to turn it off):
pending hosts with their codes, approve and reject, every host with its last
report, score and last poll, rename, revoke, **Scan now**, and a log of who did
what.

- Sign in with the token in `AGENT_STATE_DIR/admin.token` (made at the first
  start, mode 600). Delete the file and restart the receiver to change it.
- Give the page its own proxy host with TLS, reachable only from your admin
  network. It is a different port from the one the hosts use on purpose: the
  agent URL can be public, this one should not be. A login in the proxy in
  front is a good second lock; a `Remote-User` header from it is written to
  the log.
- Every change needs the session cookie and a value only the page knows, so
  another site cannot trigger it. Changes are appended to
  `AGENT_STATE_DIR/audit.log`.
- The page can approve, reject, rename, revoke and request a scan. It cannot
  change a host: there is no fix or command button, and there will not be one.

**Scan now** sets a flag. A host picks it up with `anzen --agent-poll`, which
the install script puts in cron every five minutes, and then runs a normal full
audit. The poll is signed like a report and the answer is one word, `scan` or
`idle`, so the controller still cannot name a command. The host's clock must be
right to within five minutes. From the terminal: `--agent-scan=web1`,
`--agent-rename=web1:shop`.

What the controller checks before it stores an upload: the key is approved, the
signature fits the body, every line has the exact layout anzen writes (the same
gate the dashboard uses), and the report's date is newer than the last one from
that key, so an old upload cannot be sent again. Enrolment requests wait at most
24 hours and at most 20 at a time.

What stays a matter of trust: the `curl ... | sudo sh` line runs the
controller's script as root once, at install time, so use it only with your own
controller over HTTPS. An approved host can report whatever it likes about
itself, but only under its own name. Linux hosts only for now.

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
[History & Dashboard](reports.md#history--dashboard)) for alerts on new problems and on
runs that stop happening.

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

---

[← Back to README](../README.md)
