# Plugin catalogue

Optional check modules for software anzen does not audit by default. Each
file is a regular [custom check](../docs/modules.md#custom-checks): copy the
ones you want into your `CUSTOM_CHECKS_DIR` and set their variables in
`anzen.conf`.

```bash
sudo install -d -m 755 /etc/anzen/checks.d
sudo install -m 644 plugins/backup_age.sh /etc/anzen/checks.d/
echo 'CUSTOM_CHECKS_DIR=/etc/anzen/checks.d' | sudo tee -a /etc/anzen/anzen.conf
echo 'BACKUP_AGE_PATHS="/srv/restic/snapshots:2"' | sudo tee -a /etc/anzen/anzen.conf
sudo anzen --config=/etc/anzen/anzen.conf --check=backup_age
```

`install.sh` also copies them to `/usr/local/lib/anzen/plugins`.

| Plugin | Checks | Settings |
|--------|--------|----------|
| `backup_age` | Newest backup file per location is younger than a limit | `BACKUP_AGE_PATHS`, `BACKUP_AGE_DEPTH` |
| `cert_expiry` | Expiry of certificates served by other hosts (SNI) | `CERT_EXPIRY_HOSTS`, `CERT_EXPIRY_TIMEOUT`, `TLS_WARN_DAYS`, `TLS_FAIL_DAYS` |
| `nginx_proxy_manager` | Proxy hosts without access control, without HTTPS or Force SSL; admin port 81 exposed | `NPM_DATA_DIR`, `NPM_PUBLIC_HOSTS` |

Every plugin says what it found when its settings are missing, and does
nothing else, so copying one in is harmless.

## Writing one

A plugin is `<name>.sh` defining `run_<name>_check`, using `section`, `ok`,
`warn`, `fail`, `info` and `remedy`. Keep it host-agnostic: no host names,
addresses or tokens in the file — read them from variables. Skip network
connections when `OFFLINE=true`. Add a test in `tests/test_plugins.bats` and a
row above.
