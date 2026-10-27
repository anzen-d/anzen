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
