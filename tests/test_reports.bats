#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_reports.bats — Tests for HTML, JSON and TXT report generators

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    NO_COLOR=true QUIET=true
    SCORE_FAIL_PENALTY=10
    SCORE_WARN_PENALTY=3
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET SCORE_FAIL_PENALTY SCORE_WARN_PENALTY
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_txt.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_json.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_html.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_sarif.sh"
    REPORT_OUT="$(mktemp)"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp" "$REPORT_OUT"
}

# ── TXT report ────────────────────────────────────────────────────────────────

@test "TXT report: creates file" {
    ok "fine"; fail "broken"; remedy "fix it"
    generate_txt_report "$REPORT_OUT"
    [ -f "$REPORT_OUT" ]
    [ -s "$REPORT_OUT" ]
}

@test "TXT report: contains FAIL finding" {
    fail "critical issue"
    generate_txt_report "$REPORT_OUT"
    run grep "critical issue" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "TXT report: shows Fix: for finding with remedy" {
    fail "broken"; remedy "apt-get install fix"
    generate_txt_report "$REPORT_OUT"
    run grep "Fix:" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "TXT report: contains score" {
    ok "a"; ok "b"
    generate_txt_report "$REPORT_OUT"
    run grep -i "score" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

# ── JSON report ───────────────────────────────────────────────────────────────

@test "JSON report: creates file" {
    ok "fine"
    generate_json_report "$REPORT_OUT"
    [ -f "$REPORT_OUT" ]
    [ -s "$REPORT_OUT" ]
}

@test "JSON report: is valid JSON" {
    ok "fine"; warn "hmm"; fail "bad"
    generate_json_report "$REPORT_OUT"
    run python3 -m json.tool "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "JSON report: contains findings array" {
    fail "problem"
    generate_json_report "$REPORT_OUT"
    run python3 -c "
import json, sys
d = json.load(open('$REPORT_OUT'))
assert 'findings' in d
assert len(d['findings']) > 0
"
    [ "$status" -eq 0 ]
}

@test "JSON report: finding has required fields" {
    section "SSH"
    fail "bad setting"; remedy "fix it"
    generate_json_report "$REPORT_OUT"
    run python3 -c "
import json
d = json.load(open('$REPORT_OUT'))
f = d['findings'][0]
assert 'level' in f
assert 'section' in f
assert 'message' in f
assert 'remedy' in f
"
    [ "$status" -eq 0 ]
}

@test "JSON report: remedy field is populated" {
    fail "issue"; remedy "apt-get install -y fix"
    generate_json_report "$REPORT_OUT"
    run python3 -c "
import json
d = json.load(open('$REPORT_OUT'))
f = next(x for x in d['findings'] if x['level'] == 'FAIL')
assert f['remedy'] == 'apt-get install -y fix', repr(f['remedy'])
"
    [ "$status" -eq 0 ]
}

@test "JSON report: summary score is numeric" {
    ok "a"; warn "b"; fail "c"
    generate_json_report "$REPORT_OUT"
    run python3 -c "
import json
d = json.load(open('$REPORT_OUT'))
assert isinstance(d['summary']['score'], int)
"
    [ "$status" -eq 0 ]
}

@test "JSON report: no special chars break JSON" {
    fail 'issue with "quotes" and backslash \'
    generate_json_report "$REPORT_OUT"
    run python3 -m json.tool "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

# ── HTML report ───────────────────────────────────────────────────────────────

@test "HTML report: creates file" {
    ok "fine"
    generate_html_report "$REPORT_OUT"
    [ -f "$REPORT_OUT" ]
    [ -s "$REPORT_OUT" ]
}

@test "HTML report: starts with DOCTYPE" {
    ok "fine"
    generate_html_report "$REPORT_OUT"
    run head -1 "$REPORT_OUT"
    [[ "$output" == *"DOCTYPE"* ]]
}

@test "HTML report: contains finding message" {
    fail "critical ssh misconfiguration"
    generate_html_report "$REPORT_OUT"
    run grep "critical ssh misconfiguration" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "HTML report: contains remedy in output" {
    fail "issue"; remedy "systemctl reload sshd"
    generate_html_report "$REPORT_OUT"
    run grep "systemctl reload sshd" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "HTML report: escapes < and > in findings" {
    fail "version < 2.0 detected"
    generate_html_report "$REPORT_OUT"
    # The raw < should not appear unescaped in HTML
    run grep "version < 2.0" "$REPORT_OUT"
    [ "$status" -ne 0 ]
    run grep "version &lt; 2.0\|version.*&lt;" "$REPORT_OUT"
    [ "$status" -eq 0 ]
}

@test "JSON report: findings carry IDs and sections carry scores" {
    section "SSH"; ok "fine"; fail "broken"; section "Kernel"; warn "meh"
    generate_json_report "$REPORT_OUT"
    run python3 -c "
import json
d = json.load(open('$REPORT_OUT'))
assert all(f['id'] for f in d['findings'])
assert all(0 <= s['score'] <= 100 for s in d['sections'])
"
    [ "$status" -eq 0 ]
}

@test "SARIF report: results carry finding fingerprints" {
    section "SSH"; ok "fine"; fail "broken"; warn "meh"
    generate_sarif_report "$REPORT_OUT"
    run python3 -c "
import json
d = json.load(open('$REPORT_OUT'))
r = d['runs'][0]['results']
assert r and all(x['partialFingerprints']['anzenFindingId/v1'] for x in r)
"
    [ "$status" -eq 0 ]
}

@test "HTML report: backslashes in findings are not expanded" {
    fail 'path C:\new\table'; remedy 'printf "a\tb"'
    generate_html_report "$REPORT_OUT"
    grep -qF 'path C:\new\table' "$REPORT_OUT"
    grep -qF 'printf &quot;a\tb&quot;' "$REPORT_OUT"
}
