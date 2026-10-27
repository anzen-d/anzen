# Configuration


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
| `DISTRUSTED_CERTS_FILE` | — | `truststore`: extra distrusted certificates, same format as `lib/data/distrusted-certs.tsv` |
| `TRUSTSTORE_SCAN_CONTAINERS` | `true` | `truststore`: also check the CA bundle in every running container |
| `FAIL_AS_WARN` | — | Substrings; matching FAILs are downgraded to WARN |
| `ACCEPT_FILE` | `anzen.accept` | Accepted-risk file, see [Accepted Risks](reports.md#accepted-risks) |
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

[← Back to README](../README.md)
