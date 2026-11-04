# Plugin catalogue

Optional check modules for software anzen does not audit by default. Turn
them on by name in `anzen.conf` and set their variables there:

```bash
PLUGINS="backup_age nginx_proxy_manager"
BACKUP_AGE_PATHS="/srv/restic/snapshots:2"
NPM_DATA_DIR="/opt/npm/data"
```

```bash
sudo anzen --config=/etc/anzen/anzen.conf --check=backup_age
```

They load from the `plugins/` directory next to `anzen.sh`
(`/usr/local/lib/anzen/plugins` after `install.sh`), so an update brings the
new versions. To change one, copy it into your
[`CUSTOM_CHECKS_DIR`](../docs/modules.md#custom-checks) under a new name.

| Plugin | Checks | Settings |
|--------|--------|----------|
| `backup_age` | Newest backup file per location is younger than a limit | `BACKUP_AGE_PATHS`, `BACKUP_AGE_DEPTH` |
| `cert_expiry` | Expiry of certificates served by other hosts (SNI) | `CERT_EXPIRY_HOSTS`, `CERT_EXPIRY_TIMEOUT`, `TLS_WARN_DAYS`, `TLS_FAIL_DAYS` |
| `nginx_proxy_manager` | Proxy hosts without access control, without HTTPS or Force SSL; admin port 81 exposed | `NPM_DATA_DIR`, `NPM_PUBLIC_HOSTS` |

A plugin with its settings missing only prints an INFO line, so turning one
on is harmless.

## Writing one

A plugin is `<name>.sh` defining `run_<name>_check`, using `section`, `ok`,
`warn`, `fail`, `info` and `remedy`. Keep it host-agnostic: no host names,
addresses or tokens in the file — read them from variables. Skip network
connections when `OFFLINE=true`. Add a test in `tests/test_plugins.bats` and a
row above.
