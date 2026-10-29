#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_checks_compromise.bats — drift comparison and indicators of compromise

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/drift.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/checks/compromise.sh"
    T="$BATS_TEST_TMPDIR"
}

teardown() { rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"; }

@test "_drift_compare() reports new persistence, FAIL for root keys and UID 0" {
    k=$'\t'
    printf '%s\n' "user${k}alice${k}1000:/bin/bash" "uid0${k}root${k}-" "port${k}tcp all:22${k}sshd" \
        "suid${k}/usr/bin/passwd${k}aaa" "cron${k}/etc/cron.d/backup${k}111" | sort > "$T/old"
    printf '%s\n' "user${k}alice${k}1000:/bin/bash" "uid0${k}root${k}-" "uid0${k}toor${k}-" "port${k}tcp all:22${k}sshd" \
        "port${k}tcp all:31337${k}python3" "authkey${k}root 0123456789abcdef${k}ssh-ed25519 evil@box" \
        "suid${k}/usr/bin/passwd${k}bbb" "suid${k}/tmp/.x${k}ccc" "cron${k}/etc/cron.d/backup${k}222" \
        "unit${k}/etc/systemd/system/sysupdate.service${k}ddd" | sort > "$T/new"
    _drift_compare "$T/old" "$T/new"
    grep -q $'^FAIL\t.*New UID 0 account: toor' "$FINDINGS_FILE"
    grep -q $'^FAIL\t.*New SSH key for root: ssh-ed25519 evil@box' "$FINDINGS_FILE"
    grep -q $'^FAIL\t.*New SUID/SGID binary in a temp dir: /tmp/.x' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*New listening port: tcp all:31337 (python3)' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*New systemd unit: /etc/systemd/system/sysupdate.service' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*Changed since last run: /etc/cron.d/backup' "$FINDINGS_FILE"
    # A package update replacing a SUID binary is not a warning
    grep -q $'^INFO\t.*SUID/SGID binary updated: /usr/bin/passwd' "$FINDINGS_FILE"
    [ "$_DRIFT_CHANGES" -eq 7 ]
}

@test "_drift_compare() is quiet when nothing changed, and counts removals" {
    printf 'user\talice\t1000:/bin/bash\nport\ttcp all:80\tnginx\n' > "$T/old"
    printf 'user\talice\t1000:/bin/bash\n' > "$T/new"
    _drift_compare "$T/old" "$T/new"
    [ "$_DRIFT_CHANGES" -eq 0 ]
    grep -q '1 item(s) removed since last run' "$FINDINGS_FILE"
}

@test "compromise: preload, temp-dir and memfd processes, miners" {
    printf '# comment\n/lib/x86_64-linux-gnu/libevil.so\n' > "$T/preload"
    mkdir -p "$T/proc/101" "$T/proc/102" "$T/proc/103" "$T/proc/104"
    ln -s /tmp/.kworker "$T/proc/101/exe"; echo kworker > "$T/proc/101/comm"
    ln -s "/memfd:payload (deleted)" "$T/proc/102/exe"; echo sh > "$T/proc/102/comm"
    ln -s /usr/bin/xmrig "$T/proc/103/exe"; echo xmrig > "$T/proc/103/comm"
    ln -s "/usr/sbin/sshd (deleted)" "$T/proc/104/exe"; echo sshd > "$T/proc/104/comm"
    : > "$T/proc/modules"
    ANZEN_LD_SO_PRELOAD="$T/preload" ANZEN_PROC="$T/proc" run_compromise_check
    grep -q $'^FAIL\t.*preloads into every program: /lib/x86_64-linux-gnu/libevil.so' "$FINDINGS_FILE"
    grep -q $'^FAIL\t.*Process running from a temp dir: kworker (pid 101) /tmp/.kworker' "$FINDINGS_FILE"
    grep -q $'^WARN\t.*Process running from memory (no file on disk): sh (pid 102)' "$FINDINGS_FILE"
    grep -q $'^FAIL\t.*Cryptominer process: xmrig (pid 103)' "$FINDINGS_FILE"
    grep -q $'^INFO\t.*1 process(es) still run a binary an update replaced — restart them: sshd' "$FINDINGS_FILE"
}

@test "compromise: a clean host is OK" {
    : > "$T/preload"; mkdir -p "$T/proc/1"; ln -s /usr/lib/systemd/systemd "$T/proc/1/exe"; echo systemd > "$T/proc/1/comm"
    : > "$T/proc/modules"
    ANZEN_LD_SO_PRELOAD="$T/preload" ANZEN_PROC="$T/proc" run_compromise_check
    ! grep -qE $'^(FAIL|WARN)\t' "$FINDINGS_FILE"
}
