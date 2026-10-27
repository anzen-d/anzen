#!/usr/bin/env bats
# tests/test_baseline.bats — Tests for lib/baseline.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    REPORT_DIR="$(mktemp -d)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE REPORT_DIR NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/baseline.sh"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"
    rm -rf "$REPORT_DIR"
}

@test "save_baseline() creates .baseline.json" {
    fail "some issue"
    save_baseline
    [ -f "$REPORT_DIR/.baseline.json" ]
}

@test "save_baseline() produces valid JSON" {
    fail "issue a"; ok "fine b"
    save_baseline
    run python3 -m json.tool "$REPORT_DIR/.baseline.json"
    [ "$status" -eq 0 ]
}

@test "save_baseline() includes fails array" {
    fail "ssh root login enabled"
    save_baseline
    run python3 -c "
import json
d = json.load(open('$REPORT_DIR/.baseline.json'))
assert 'fails' in d
assert len(d['fails']) == 1
"
    [ "$status" -eq 0 ]
}

@test "diff_baseline() exits 0 when no regressions" {
    fail "known issue"
    save_baseline
    # Same failures — no regression
    run diff_baseline
    [ "$status" -eq 0 ]
}

@test "diff_baseline() exits 1 on new failure" {
    fail "old issue"
    save_baseline
    # Add a new failure
    fail "NEW issue"
    run diff_baseline
    [ "$status" -eq 1 ]
}

@test "diff_baseline() reports new failure in output" {
    fail "old issue"
    save_baseline
    fail "NEW regression"
    run diff_baseline
    [[ "$output" == *"NEW regression"* ]]
}

@test "diff_baseline() exits 0 when issue is resolved" {
    fail "old issue"
    save_baseline
    # Clear findings — old issue resolved
    : > "$FINDINGS_FILE"
    run diff_baseline
    [ "$status" -eq 0 ]
}

@test "diff_baseline() reports resolved issues" {
    fail "old issue"
    save_baseline
    : > "$FINDINGS_FILE"
    run diff_baseline
    [[ "$output" == *"old issue"* ]]
}

@test "diff_baseline() fails gracefully when no baseline exists" {
    run diff_baseline
    [ "$status" -ne 0 ]
    [[ "$output" == *"baseline"* ]] || [[ "$output" == *"No baseline"* ]]
}

@test "diff_baseline() round-trips quoted messages" {
    fail 'path "/etc/x" has \ odd chars'; fail "plain issue"
    save_baseline
    run diff_baseline
    [ "$status" -eq 0 ]
    [[ "$output" == *"No changes since baseline"* ]]
}

@test "diff_baseline() matches by ID, so volatile numbers are not regressions" {
    section "System"; fail "Disk / at 91% used"
    save_baseline
    : > "$FINDINGS_FILE"
    section "System"; fail "Disk / at 95% used"
    run diff_baseline
    [ "$status" -eq 0 ]
    [[ "$output" == *"No changes since baseline"* ]]
}

@test "diff_baseline() falls back to messages for pre-0.5 baselines" {
    printf '{\n  "date": "x",\n  "fails": [\n    "old issue",\n    "kept issue"\n  ],\n  "fail_count": 2\n}\n' \
        > "$REPORT_DIR/.baseline.json"
    fail "kept issue"; fail "brand new"
    run diff_baseline
    [ "$status" -eq 1 ]
    [[ "$output" == *"re-run --baseline"* ]]
    [[ "$output" == *"+ brand new"* ]]
    [[ "$output" == *"- old issue"* ]]
    [[ "$output" != *"kept issue"* ]]
}
