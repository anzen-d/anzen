#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
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
    # --check runs are saved only with an explicit --history=
    run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --history="$T/hist" --remote=root@alpha,beta --check=kernel --quiet --no-color
    [ "$status" -ne 255 ]
    # Both runs report the local hostname, so one history dir holds two runs
    [ "$(ls "$T"/hist/*/*.json | wc -l)" -eq 2 ]
    [ -f "$T/dash.html" ]
    grep -qx 'root@alpha' "$T/ssh.log"
    grep -qx 'beta' "$T/ssh.log"
}

@test "fleet: a --check run without --history= stays out of history" {
    run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --remote=h1 --check=kernel --quiet --no-color
    [ "$status" -ne 255 ]
    [ ! -d "$T/hist" ] || [ -z "$(ls -A "$T/hist")" ]
    [ ! -f "$T/dash.html" ]
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

@test "fleet: a macOS host runs the macOS edition and lands in history" {
    local stubs="$ANZEN_DIR/tests/macos/stubs"
    # Fake Mac: uname -s says Darwin, macOS commands come from the test stubs
    cat > "$T/sshmac" <<SH
#!/bin/bash
while [ "\$1" = "-o" ]; do shift 2; done
shift
[ "\$*" = "uname -s" ] && { echo Darwin; exit 0; }
exec env -i PATH="$stubs:\$PATH" HOME="$T" NO_COLOR=1 bash -c "\$*"
SH
    chmod +x "$T/sshmac"
    ANZEN_SSH="$T/sshmac" run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --history="$T/hist" --remote=mac1 --html --quiet --no-color
    [ "$status" -ne 255 ]
    local f; f=$(ls "$T"/hist/*/*.json | head -1)
    grep -q '"os": "macOS ' "$f"
    grep -q '"section": "FileVault"' "$f"
    ls "$ANZEN_DIR"/reports/anzen_*.html >/dev/null
    grep -l 'macOS Security Audit' "$ANZEN_DIR"/reports/anzen_*.html | xargs rm -f
}

@test "fleet: a Windows host runs the Windows edition over one PowerShell session" {
    command -v iconv >/dev/null || skip "iconv not installed"
    # Fake Windows OpenSSH: no uname; decodes -EncodedCommand, answers the OS
    # probe, and for the audit checks the files sent on stdin and returns a
    # Windows report as "json<TAB>base64" plus the exit code
    cp "$ANZEN_DIR/docs/demo/history/desktop-win11/20261027T040000Z.json" "$T/win.json"
    cat > "$T/sshwin" <<SH
#!/bin/bash
while [ "\$1" = "-o" ]; do shift 2; done
shift
case "\$*" in
    "uname -s") echo "'uname' is not recognized" >&2; exit 1 ;;
    "powershell -NoProfile -NonInteractive -EncodedCommand "*) ;;
    *) exit 1 ;;
esac
ps=\$(printf '%s' "\${*##* }" | base64 -d | iconv -f UTF-16LE -t UTF-8)
printf '%s\n' "\$ps" >> "$T/ps.log"
case \$ps in *OSVersion.Platform*) printf 'Win32NT\r\n'; exit 0 ;; esac
cat > "$T/stdin"
printf 'json\t%s\r\nrc\t1\r\n' "\$(base64 < "$T/win.json" | tr -d '\n')"
SH
    chmod +x "$T/sshwin"
    printf 'containers-security-0123abcd  2099-01-01  test\n' > "$T/acc"
    printf 'ACCEPT_FILE=%s/acc\n' "$T" >> "$T/c.conf"
    ANZEN_SSH="$T/sshwin" run "$ANZEN_DIR/anzen.sh" --config="$T/c.conf" --history="$T/hist" \
        --remote=admin@win1 --check=defender --strict --quiet --no-color
    [ "$status" -eq 1 ]
    ls "$T"/hist/desktop-win11/*.json
    cut -f1 "$T/stdin" | sort | tr '\n' ' ' | grep -qx 'lib/data/controls.tsv lib/data/distrusted-certs.tsv lib/data/ioc.tsv windows/anzen.accept windows/anzen.ps1 '
    grep "^windows/anzen.accept	" "$T/stdin" | cut -f2 | base64 -d | grep -q containers-security-0123abcd
    grep -q '"-Check"; $a += "defender"' "$T/ps.log"
    grep -q 'if ("1" -eq "1") { $a += "-Strict" }' "$T/ps.log"
}
