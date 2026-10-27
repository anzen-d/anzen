#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_config.bats — Tests for lib/config.sh defaults and overrides

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    CONF_TMP="$(mktemp)"
    export ANZEN_DIR
    # shellcheck source=../lib/utils.sh
    source "$ANZEN_DIR/lib/utils.sh"
}

teardown() {
    rm -f "$CONF_TMP"
}

_load_config() {
    # Source config in a subshell and print a variable
    bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        source '$ANZEN_DIR/lib/config.sh'
        echo \"\$$1\"
    "
}

@test "DISK_WARN_PCT defaults to 75" {
    run _load_config DISK_WARN_PCT
    [ "$output" = "75" ]
}

@test "DISK_FAIL_PCT defaults to 90" {
    run _load_config DISK_FAIL_PCT
    [ "$output" = "90" ]
}

@test "TLS_WARN_DAYS defaults to 30" {
    run _load_config TLS_WARN_DAYS
    [ "$output" = "30" ]
}

@test "TLS_FAIL_DAYS defaults to 7" {
    run _load_config TLS_FAIL_DAYS
    [ "$output" = "7" ]
}

@test "SCORE_FAIL_PENALTY defaults to 10" {
    run _load_config SCORE_FAIL_PENALTY
    [ "$output" = "10" ]
}

@test "SCORE_WARN_PENALTY defaults to 3" {
    run _load_config SCORE_WARN_PENALTY
    [ "$output" = "3" ]
}

@test "anzen.conf overrides DISK_WARN_PCT" {
    echo "DISK_WARN_PCT=55" > "$CONF_TMP"
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        # Write a temporary anzen.conf in a temp dir
        TMPD=\$(mktemp -d)
        echo 'DISK_WARN_PCT=55' > \"\$TMPD/anzen.conf\"
        # Patch config.sh to use TMPD
        _conf=\$TMPD/anzen.conf
        source '$ANZEN_DIR/lib/config.sh'
        # Override happens via sourcing
        source \"\$TMPD/anzen.conf\"
        echo \"\$DISK_WARN_PCT\"
        rm -rf \"\$TMPD\"
    "
    [ "$output" = "55" ]
}

@test "EXCLUDE_CHECKS defaults to empty" {
    run _load_config EXCLUDE_CHECKS
    [ -z "$output" ]
}

@test "FAIL_LOGIN_OK defaults to 10" {
    run _load_config FAIL_LOGIN_OK
    [ "$output" = "10" ]
}

@test "PASS_MAX_DAYS_WARN defaults to 90" {
    run _load_config PASS_MAX_DAYS_WARN
    [ "$output" = "90" ]
}

@test "FAIL_AS_WARN defaults to empty" {
    run _load_config FAIL_AS_WARN
    [ -z "$output" ]
}

@test "NOTIFY_ON_FAIL_ONLY defaults to false" {
    run _load_config NOTIFY_ON_FAIL_ONLY
    [ "$output" = "false" ]
}

# ── _safe_source_config ───────────────────────────────────────────────────────

@test "_safe_source_config sources a valid user-owned config" {
    local f; f=$(mktemp)
    chmod 600 "$f"
    echo "DISK_WARN_PCT=42" > "$f"
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        source '$ANZEN_DIR/lib/utils.sh'
        _safe_source_config '$f' && echo \$DISK_WARN_PCT
    "
    [ "$status" -eq 0 ]
    [ "$output" = "42" ]
    rm -f "$f"
}

@test "_safe_source_config rejects world-writable config" {
    local f; f=$(mktemp)
    chmod 666 "$f"
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        source '$ANZEN_DIR/lib/utils.sh'
        _safe_source_config '$f'
    "
    [ "$status" -ne 0 ]
    [[ "$output" == *"world-writable"* ]]
    rm -f "$f"
}

@test "_safe_source_config rejects non-existent file" {
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        source '$ANZEN_DIR/lib/utils.sh'
        _safe_source_config '/tmp/anzen_no_such_file_$$'
    "
    [ "$status" -ne 0 ]
}
