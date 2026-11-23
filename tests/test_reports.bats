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
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_csv.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/controls.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/lessons.sh"
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

@test "JSON report: control characters in a message keep it valid JSON" {
    fail "banner $(printf '\033[1mSSH-2.0\001')"
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

# ── Controls and CSV ──────────────────────────────────────────────────────────

@test "controls: first matching mapping per finding, one line per finding" {
    section "SSH Configuration"; fail "PermitRootLogin yes"; warn "X11Forwarding enabled"
    section "Made Up Section"; warn "anything"
    run _findings_controls
    [ "${lines[0]}" = "NIST AC-6(2), IA-2; CIS 5.4" ]
    [ "${lines[1]}" = "NIST AC-17, CM-6; CIS 4.1" ]
    [ "${#lines[@]}" -eq 3 ] || [ -z "${lines[2]:-}" ]
    [ "$(_findings_controls | wc -l)" -eq 3 ]
}

@test "controls: every section of every edition has a mapping" {
    local secs s missing=""
    secs=$( { grep -rhoE 'section "[^"$]+' "$ANZEN_DIR"/lib/checks/*.sh "$ANZEN_DIR"/macos/anzen-macos.sh | sed 's/^section "//'
              grep -hoE "Section '[^']+'" "$ANZEN_DIR/windows/anzen.ps1" | sed "s/^Section '//; s/'\$//"; } | sort -u)
    while IFS= read -r s; do
        case $s in "System Information"|Inventory|"Pentest External — Port Scan: "|"Pentest External — Recon: "|"Pentest External — TLS/SSL: ") continue ;; esac
        printf 'WARN\t%s\tx\tid\t\n' "$s" > "$FINDINGS_FILE"
        [ -n "$(_findings_controls)" ] || missing="$missing [$s]"
    done <<< "$secs"
    [ -z "$missing" ] || { echo "no mapping for:$missing"; false; }
}

@test "TXT, HTML and SARIF reports carry the control references" {
    section "SSH Configuration"; fail "PermitRootLogin yes"; remedy "fix"
    generate_txt_report "$REPORT_OUT"
    grep -q '         Ref: NIST AC-6(2), IA-2; CIS 5.4' "$REPORT_OUT"
    generate_html_report "$REPORT_OUT"
    grep -q 'ssh-configuration-[0-9a-f]* · NIST AC-6(2), IA-2; CIS 5.4' "$REPORT_OUT"
    generate_sarif_report "$REPORT_OUT"
    grep -q '"properties":{"controls":"NIST AC-6(2), IA-2; CIS 5.4"}' "$REPORT_OUT"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$REPORT_OUT"
}

@test "CSV report: quotes fields and defuses spreadsheet formulas" {
    section "SSH Configuration"; fail 'say "hi", then go'; remedy "=HYPERLINK(\"x\")"
    section "Made Up Section"; warn "-1 is fine"
    generate_csv_report "$REPORT_OUT"
    run python3 -c '
import csv, sys
rows = list(csv.reader(open(sys.argv[1], newline="")))
assert rows[0] == ["host","date","level","section","id","message","remedy","controls"], rows[0]
assert rows[1][2:4] == ["FAIL", "SSH Configuration"] and rows[1][5] == "say \"hi\", then go", rows[1]
assert rows[1][6] == "\x27=HYPERLINK(\"x\")" and rows[1][7].startswith("NIST AC-17"), rows[1]
assert rows[2][5] == "\x27-1 is fine" and rows[2][7] == "", rows[2]
print(len(rows))' "$REPORT_OUT"
    [ "$status" -eq 0 ] || { echo "$output"; false; }
    [ "$output" = 3 ]
}

# ── Lessons (lib/data/lessons.tsv) ───────────────────────────────────────────

@test "lessons: first matching lesson per finding, one line per finding" {
    section "SSH Configuration"; fail "PermitRootLogin: yes — direct root SSH login allowed"
    warn "SSH on default port 22"
    section "Users & Sudo"; fail "NOPASSWD: ALL — full root without a password prompt"
    run _findings_lessons
    [ "${#lines[@]}" -eq 2 ]
    [[ "${lines[0]}" == "Root login over SSH"$'\t'* ]]
    [[ "${lines[1]}" == "sudo without a password"$'\t'* ]]
    [ "$(_findings_lessons | wc -l)" -eq 3 ]
    [ "$(_findings_lessons | sed -n 2p)" = "" ]
}

@test "lessons: every line has six fields, none empty" {
    run awk -F'\t' '/^[[:space:]]*(#|$)/ { next }
        { if (NF != 6) { print "line " NR ": " NF " fields"; bad = 1 }
          for (i = 1; i <= NF; i++) if ($i ~ /^[[:space:]]*$/) { print "line " NR ": field " i " is empty"; bad = 1 } }
        END { exit bad }' "$ANZEN_DIR/lib/data/lessons.tsv"
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "lessons: every lesson still matches a section and a message of the checks" {
    # A lesson whose check was renamed or removed must fail here, not rot
    local sections msgs sre mre title dead=""
    sections=$(grep -rhoE '^[[:space:]]*section "[^"]+"' "$ANZEN_DIR"/lib/checks | sed -e 's/^[[:space:]]*section "//' -e 's/"$//')
    msgs=$(grep -rhE '(fail|warn) "|expl = "' "$ANZEN_DIR"/lib/checks)
    while IFS=$'\t' read -r sre mre title _; do
        case "$sre" in ''|'#'*) continue ;; esac
        grep -qiE "^($sre)$" <<< "$sections" || dead="$dead [section: $title]"
        grep -qiE "$mre" <<< "$msgs" || dead="$dead [message: $title]"
    done < "$ANZEN_DIR/lib/data/lessons.tsv"
    echo "lessons that match nothing:$dead"
    [ -z "$dead" ]
}

@test "lessons: HTML report shows the lesson under a FAIL, not under an OK" {
    section "SSH Configuration"
    fail "PermitRootLogin: yes — direct root SSH login allowed"; remedy "echo fix"
    ok "PermitRootLogin: yes would be bad"
    generate_html_report "$REPORT_OUT"
    [ "$(grep -c '<details class="lesson" id="lesson-1">' "$REPORT_OUT")" -eq 1 ]
    grep -q 'Why it matters: Root login over SSH' "$REPORT_OUT"
    grep -q 'Before you change it' "$REPORT_OUT"
    grep -q 'Check that it worked' "$REPORT_OUT"
    grep -q "details:not(.lesson)" "$REPORT_OUT"
}

@test "lessons: the text is in the page once, later findings link to it" {
    section "Container Security"
    warn "[docker] Running as root: web  [CIS 5.1]"
    warn "[docker] Running as root: db  [CIS 5.1]"
    warn "[docker] Running as root: cache  [CIS 5.1]"
    fail "[docker] Privileged container: web  [CIS 5.4]"
    generate_html_report "$REPORT_OUT"
    [ "$(grep -c '<details class="lesson" id="lesson-1">' "$REPORT_OUT")" -eq 1 ]
    [ "$(grep -c '<details class="lesson" id="lesson-2">' "$REPORT_OUT")" -eq 1 ]
    [ "$(grep -c 'class="lesson-ref" href="#lesson-1"' "$REPORT_OUT")" -eq 2 ]
    [ "$(grep -o 'Root in a container is the same user' "$REPORT_OUT" | wc -l)" -eq 1 ]
}

@test "lessons: text from the lesson file is escaped in the HTML report" {
    printf 'Demo\t.\t<b>T</b>\t<script>alert(1)</script>\tA & B\techo "x" > /dev/null\n' > "$BATS_TEST_TMPDIR/l.tsv"
    section "Demo"; fail "something"
    ANZEN_LESSONS_FILE="$BATS_TEST_TMPDIR/l.tsv" generate_html_report "$REPORT_OUT"
    grep -q '&lt;script&gt;alert(1)&lt;/script&gt;' "$REPORT_OUT"
    grep -q 'Why it matters: &lt;b&gt;T&lt;/b&gt;' "$REPORT_OUT"
    ! grep -q '<script>alert(1)' "$REPORT_OUT"
}

@test "lessons: a report without the lesson file has no lesson and no error" {
    section "SSH Configuration"; fail "PermitRootLogin: yes — direct root SSH login allowed"
    ANZEN_LESSONS_FILE=/nonexistent run generate_html_report "$REPORT_OUT"
    [ "$status" -eq 0 ]
    ! grep -q '<details class="lesson"' "$REPORT_OUT"
}

@test "lessons: lesson_explain prints the finding, its fix and its lesson" {
    section "SSH Configuration"
    fail 'PermitRootLogin: yes — "root" login allowed (C:\x)'; remedy "sed -i 's/yes/no/' /etc/ssh/sshd_config"
    warn "SSH on default port 22"
    generate_json_report "$REPORT_OUT"
    id=$(awk -F'\t' '$1 == "FAIL" { print $4 }' "$FINDINGS_FILE")
    run lesson_explain "$id" "$REPORT_OUT"
    [ "$status" -eq 0 ]
    [[ "$output" == *'PermitRootLogin: yes — "root" login allowed (C:\x)'* ]]
    [[ "$output" == *"sed -i 's/yes/no/' /etc/ssh/sshd_config"* ]]
    [[ "$output" == *"Root login over SSH"* && "$output" == *"Check that it worked"* && "$output" == *"Ref: NIST"* ]]
    # No lesson for this one, still the finding itself
    id=$(awk -F'\t' '$1 == "WARN" { print $4 }' "$FINDINGS_FILE")
    run lesson_explain "$id" "$REPORT_OUT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"No lesson for this finding yet."* ]]
    run lesson_explain "no-such-id" "$REPORT_OUT"
    [ "$status" -eq 1 ]
    [ -z "$output" ]
}

@test "lessons: _lessons_js is valid JSON and cannot end the script block" {
    printf 'Demo|X\t"q"\\\\.\tT</script><script>alert(1)\twhy\trisk\techo "x"\n# c\nshort\tline\n' > "$BATS_TEST_TMPDIR/l.tsv"
    ANZEN_LESSONS_FILE="$BATS_TEST_TMPDIR/l.tsv" _lessons_js > "$REPORT_OUT"
    ! grep -q '</script>' "$REPORT_OUT"
    run python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d) == 1 and len(d[0]) == 6, d
assert d[0][1] == "\"q\"\\\\." and d[0][2] == "T</script><script>alert(1)" and d[0][5] == "echo \"x\"", d' "$REPORT_OUT"
    [ "$status" -eq 0 ] || { echo "$output"; false; }
    [ "$(ANZEN_LESSONS_FILE=/nonexistent _lessons_js)" = "[]" ]
}
