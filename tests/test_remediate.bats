#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_remediate.bats — Tests for lib/remediate.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/remediate.sh"
    REMEDIATE_OUT="$(mktemp)"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp" "$REMEDIATE_OUT"
}

@test "generate_remediate_script() creates executable script" {
    fail "issue"; remedy "apt-get install fix"
    generate_remediate_script "$REMEDIATE_OUT"
    [ -f "$REMEDIATE_OUT" ]
    [ -x "$REMEDIATE_OUT" ]
}

@test "generate_remediate_script() includes shebang" {
    fail "issue"; remedy "echo fix"
    generate_remediate_script "$REMEDIATE_OUT"
    run head -1 "$REMEDIATE_OUT"
    [[ "$output" == "#!/bin/bash" ]]
}

@test "generate_remediate_script() includes set -euo pipefail" {
    fail "issue"; remedy "echo fix"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "set -euo pipefail" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() includes remedy command" {
    fail "issue"; remedy "apt-get install -y nginx"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "apt-get install -y nginx" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() skips OK findings" {
    ok "fine"; fail "broken"; remedy "fix it"
    generate_remediate_script "$REMEDIATE_OUT"
    # only the FAIL remedy should appear, not the ok message
    run grep "fine" "$REMEDIATE_OUT"
    [ "$status" -ne 0 ]
}

@test "generate_remediate_script() skips findings without remedy" {
    fail "no remedy here"
    generate_remediate_script "$REMEDIATE_OUT"
    # file should exist but have no executable commands beyond header
    run grep -c "^[^#]" "$REMEDIATE_OUT"
    # only the set -euo pipefail and possibly the echo lines — not the finding message
    [ "${output:-0}" -lt 5 ]
}

@test "generate_remediate_script() returns count of remedies" {
    fail "a"; remedy "fix a"
    fail "b"; remedy "fix b"
    ok "c"
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR'
        FINDINGS_FILE='$FINDINGS_FILE'
        source '$ANZEN_DIR/lib/output.sh'
        source '$ANZEN_DIR/lib/remediate.sh'
        generate_remediate_script '$REMEDIATE_OUT'
    "
    # count written to stdout
    [ "$output" = "2" ]
}

@test "generate_remediate_script() groups by section" {
    section "SSH"
    fail "ssh issue"; remedy "systemctl reload sshd"
    section "Kernel"
    fail "kernel issue"; remedy "sysctl -w net.ipv4.tcp_syncookies=1"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "SSH" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
    run grep "Kernel" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}

@test "generate_remediate_script() handles special chars in remedy" {
    fail "issue"
    remedy "sed -i \"s/#PermitRootLogin yes/PermitRootLogin no/\" /etc/ssh/sshd_config"
    generate_remediate_script "$REMEDIATE_OUT"
    run grep "sshd_config" "$REMEDIATE_OUT"
    [ "$status" -eq 0 ]
}
