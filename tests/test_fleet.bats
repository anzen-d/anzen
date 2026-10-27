#!/usr/bin/env bats
# tests/test_fleet.bats — --remote fleet mode with a local stand-in for ssh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    T="$(mktemp -d)"
    # Fake ssh: skip "-o X" options and the host, run the command locally
    cat > "$T/ssh" <<'SH'
#!/bin/bash
while [ "$1" = "-o" ]; do shift 2; done
host=$1; shift
echo "$host" >> "${FAKE_SSH_LOG:-/dev/null}"
# Real ssh starts the remote command with a fresh environment
exec env -i PATH="$PATH" HOME="$HOME" bash -c "$*"
SH
    chmod +x "$T/ssh"
    printf 'HISTORY_DIR=%s/hist\nDASHBOARD_FILE=%s/dash.html\nDISK_WARN_PCT=71\n' "$T" "$T" > "$T/c.conf"
    chmod 600 "$T/c.conf"
    export ANZEN_SSH="$T/ssh" FAKE_SSH_LOG="$T/ssh.log"
}

teardown() { rm -rf "$T"; }

@test "fleet: each host's JSON lands in history, dashboard is built" {
    run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --remote=root@alpha,beta --check=kernel --quiet --no-color
    [ "$status" -ne 255 ]
    # Both runs report the local hostname, so one history dir holds two runs
    [ "$(ls "$T"/hist/*/*.json | wc -l)" -eq 2 ]
    [ -f "$T/dash.html" ]
    grep -qx 'root@alpha' "$T/ssh.log"
    grep -qx 'beta' "$T/ssh.log"
}

@test "fleet: remote gets scan settings only, and cleans up" {
    printf 'NOTIFY_NTFY_URL=http://secret.invalid/x\n' >> "$T/c.conf"
    # Capture the generated conf by wrapping the fake ssh
    cat > "$T/ssh2" <<SH
#!/bin/bash
args="\$*"
[[ "\$args" == *"cat > "*anzen.conf* ]] && { cat > "$T/shipped.conf"; exit 0; }
exec "$T/ssh" "\$@"
SH
    chmod +x "$T/ssh2"
    ANZEN_SSH="$T/ssh2" run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --remote=h1 --check=kernel --quiet --no-color
    grep -q '^DISK_WARN_PCT=71$' "$T/shipped.conf"
    ! grep -q 'NOTIFY\|HISTORY\|DASHBOARD' "$T/shipped.conf"
    [ -z "$(ls -d /tmp/anzen.* 2>/dev/null)" ] || ! ls -d /tmp/anzen.*/anzen.sh 2>/dev/null | grep -q .
}

@test "fleet: invalid host names are rejected before any connection" {
    run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" '--remote=ok,bad;rm -rf /' --check=kernel
    [ "$status" -eq 255 ]
    [ ! -s "$T/ssh.log" ]
}

@test "fleet: --html --output= for one host returns the HTML report" {
    run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --remote=h1 --check=kernel --quiet --no-color \
        --html --output="$T/remote.html"
    grep -qi '<!DOCTYPE html>' "$T/remote.html"
}
