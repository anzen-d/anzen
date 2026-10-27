#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_output.bats — Tests for lib/output.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true
    QUIET=false
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"
}

# ── _record / level functions ─────────────────────────────────────────────────

@test "ok() writes OK tab-separated finding" {
    ok "all good"
    run grep "^OK	" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"all good"* ]]
}

@test "warn() writes WARN finding" {
    warn "something odd"
    run grep "^WARN	" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"something odd"* ]]
}

@test "fail() writes FAIL finding" {
    fail "bad thing"
    run grep "^FAIL	" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"bad thing"* ]]
}

@test "info() writes INFO finding" {
    info "just fyi"
    run grep "^INFO	" "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [[ "$output" == *"just fyi"* ]]
}

@test "section() sets CURRENT_SECTION" {
    section "SSH"
    [ "$CURRENT_SECTION" = "SSH" ]
}

@test "findings include section field" {
    section "TestSection"
    ok "msg"
    local line; line=$(tail -1 "$FINDINGS_FILE")
    IFS=$'\t' read -r lvl sec msg _ <<< "$line"
    [ "$sec" = "TestSection" ]
    [ "$msg" = "msg" ]
}

@test "findings have 5 tab-separated fields" {
    ok "five fields"
    local line; line=$(tail -1 "$FINDINGS_FILE")
    local count; count=$(echo "$line" | awk -F'\t' '{print NF}')
    [ "$count" -eq 5 ]
}

@test "remedy() keeps backslashes in the command" {
    fail "x"
    remedy 'sed -i "s/a\\tb/c/" f \\ next'
    IFS=$'\t' read -r _ _ _ _ rem < "$FINDINGS_FILE"
    [ "$rem" = 'sed -i "s/a\\tb/c/" f \\ next' ]
}

@test "remedy() fills the 5th field and keeps the ID" {
    section "SSH"; fail "root login"
    remedy "fix it"
    IFS=$'\t' read -r level sec msg id rem < "$FINDINGS_FILE"
    [ "$id" = "$(_finding_id SSH "root login")" ]
    [ "$rem" = "fix it" ]
}

# ── finding IDs ───────────────────────────────────────────────────────────────

@test "_finding_id() ignores volatile numbers" {
    [ "$(_finding_id System "Disk / at 81% used")" = "$(_finding_id System "Disk / at 93% used")" ]
    [ "$(_finding_id System "Uptime 12 days")" = "$(_finding_id System "Uptime 40 days")" ]
    [ "$(_finding_id Users "3 accounts without password")" = "$(_finding_id Users "5 accounts without password")" ]
}

@test "_finding_id() keeps subjects apart" {
    [ "$(_finding_id Network "Port 22 open")" != "$(_finding_id Network "Port 8080 open")" ]
    [ "$(_finding_id Docker "No memory limit: a")" != "$(_finding_id Docker "No memory limit: b")" ]
    [ "$(_finding_id SSH "x")" != "$(_finding_id Kernel "x")" ]
}

@test "_finding_id() is prefixed with the section slug" {
    [[ "$(_finding_id "Container Security" "x")" == container-security-* ]]
}

# ── accepted risks ────────────────────────────────────────────────────────────

@test "accepted FAIL is recorded as INFO with the reason" {
    section "Docker"
    printf '%s 2999-01-01 needed by portainer\n' "$(_finding_id Docker "sock mounted")" > "$BATS_TEST_TMPDIR/accept"
    load_accepted "$BATS_TEST_TMPDIR/accept"
    fail "sock mounted"
    run grep -c "^FAIL" "$FINDINGS_FILE"
    [ "$output" = "0" ]
    run grep "^INFO" "$FINDINGS_FILE"
    [[ "$output" == *"accepted until 2999-01-01: needed by portainer"* ]]
}

@test "expired acceptance keeps FAIL and the original ID" {
    section "Docker"
    local id; id=$(_finding_id Docker "sock mounted")
    printf '%s 2000-01-01 old excuse\n' "$id" > "$BATS_TEST_TMPDIR/accept"
    load_accepted "$BATS_TEST_TMPDIR/accept"
    fail "sock mounted"
    run grep "^FAIL" "$FINDINGS_FILE"
    [[ "$output" == *"acceptance expired 2000-01-01"* ]]
    [[ "$output" == *"$id"* ]]
}

@test "accept entry without a date is ignored" {
    section "Docker"
    printf '%s forever\n' "$(_finding_id Docker "sock mounted")" > "$BATS_TEST_TMPDIR/accept"
    run load_accepted "$BATS_TEST_TMPDIR/accept"
    [[ "$output" == *"needs an expiry date"* ]]
    load_accepted "$BATS_TEST_TMPDIR/accept" 2>/dev/null
    fail "sock mounted"
    run grep -c "^FAIL" "$FINDINGS_FILE"
    [ "$output" = "1" ]
}

@test "info() is suppressed when QUIET=true" {
    QUIET=true
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE' NO_COLOR=true QUIET=true
        source '$ANZEN_DIR/lib/output.sh'
        info 'silent'
    "
    [[ "$output" != *"silent"* ]]
}

@test "info() is shown when QUIET=false" {
    run bash -c "
        ANZEN_DIR='$ANZEN_DIR' FINDINGS_FILE='$FINDINGS_FILE' NO_COLOR=true QUIET=false
        source '$ANZEN_DIR/lib/output.sh'
        info 'visible'
    "
    [[ "$output" == *"visible"* ]]
}

# ── remedy() ──────────────────────────────────────────────────────────────────

@test "remedy() appends command to last finding" {
    fail "something broken"
    remedy "apt-get install fix"
    local line; line=$(tail -1 "$FINDINGS_FILE")
    IFS=$'\t' read -r _ _ _ _ rem <<< "$line"
    [ "$rem" = "apt-get install fix" ]
}

@test "remedy() only modifies last line" {
    ok "first"
    fail "second"
    remedy "fix second"
    # first line should still have empty remedy
    local first; first=$(head -1 "$FINDINGS_FILE")
    IFS=$'\t' read -r _ _ _ _ rem <<< "$first"
    [ -z "$rem" ]
}

@test "remedy() on empty file does nothing" {
    run remedy "should not error"
    [ "$status" -eq 0 ]
}

@test "remedy() handles special characters in command" {
    fail "issue"
    remedy "sed -i 's/foo/bar/g' /etc/ssh/sshd_config"
    local line; line=$(tail -1 "$FINDINGS_FILE")
    IFS=$'\t' read -r _ _ _ _ rem <<< "$line"
    [[ "$rem" == *"sshd_config"* ]]
}

# ── print_summary() ───────────────────────────────────────────────────────────

@test "print_summary() shows correct FAIL count" {
    fail "a"; fail "b"
    run print_summary
    [[ "$output" == *"FAIL: 2"* ]]
}

@test "print_summary() score is 100 with no findings" {
    run print_summary
    [[ "$output" == *"Score:"*"100%"* ]]
}

@test "print_summary() score deducts 10 per FAIL" {
    SCORE_FAIL_PENALTY=10
    SCORE_WARN_PENALTY=3
    export SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
    fail "one"
    run print_summary
    [[ "$output" == *"Score:"*"90%"* ]]
}

@test "print_summary() score deducts 3 per WARN" {
    SCORE_FAIL_PENALTY=10
    SCORE_WARN_PENALTY=3
    export SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
    warn "one"
    run print_summary
    [[ "$output" == *"Score:"*"97%"* ]]
}

@test "overall score is the mean of section scores" {
    SCORE_FAIL_PENALTY=10 SCORE_WARN_PENALTY=3
    export SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
    section "Noisy"; for i in $(seq 1 40); do warn "w $i"; done
    section "Clean"; ok "fine"
    [ "$(_overall_score)" = "50" ]
}

@test "print_summary() groups repeated findings" {
    section "Docker"
    for c in a b c d; do warn "No memory limit: $c"; done
    run print_summary
    [[ "$output" == *"4× WARN No memory limit"* ]]
}

@test "print_summary() score floors at 0" {
    SCORE_FAIL_PENALTY=10
    SCORE_WARN_PENALTY=3
    export SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
    for i in $(seq 1 20); do fail "issue $i"; done
    run print_summary
    [[ "$output" == *"Score:"*"0%"* ]]
}

@test "print_summary() groups on ': ' so versions and ports do not split prefixes" {
    section "X"
    for p in 1 2 3; do warn ":80$p — Missing CSP"; warn "libcap2 1:2.6$p in host: 1 HIGH"; done
    run _repeated_findings 3
    [ -z "$output" ]
}
