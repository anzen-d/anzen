#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_history.bats — Tests for lib/history.sh

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    FINDINGS_FILE="$(mktemp)"
    HIST="$(mktemp -d)"
    NO_COLOR=true QUIET=true
    export ANZEN_DIR FINDINGS_FILE NO_COLOR QUIET
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/output.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/report_json.sh"
    # shellcheck disable=SC1091
    source "$ANZEN_DIR/lib/history.sh"
}

teardown() {
    rm -f "$FINDINGS_FILE" "${FINDINGS_FILE}.tmp"
    rm -rf "$HIST"
}

@test "history_save() writes a JSON report under the host dir" {
    section "SSH"; fail "root login"
    out=$(history_save "$HIST")
    [ -f "$out" ]
    [[ "$out" == "$HIST/$(hostname -s)/"*.json ]]
    python3 -m json.tool "$out" >/dev/null
}

@test "history_save() keeps only HISTORY_KEEP runs" {
    d="$HIST/$(hostname -s)"; mkdir -p "$d"
    for i in 1 2 3 4; do echo '{}' > "$d/2020010${i}T000000Z.json"; done
    HISTORY_KEEP=2 history_save "$HIST" >/dev/null
    [ "$(ls "$d" | wc -l)" -eq 2 ]
    [ ! -f "$d/20200101T000000Z.json" ]
}

@test "history_new_fails() reports every FAIL when there is no previous run" {
    section "SSH"; fail "a"; fail "b"; warn "c"
    run history_new_fails ""
    [ "${#lines[@]}" -eq 2 ]
}

@test "history_new_fails() reports only FAILs absent from the previous run" {
    section "SSH"; fail "old one"; fail 'quoted "x" \ y'
    prev=$(history_save "$HIST")
    : > "$FINDINGS_FILE"
    section "SSH"; fail "old one"; fail 'quoted "x" \ y'; fail "brand new"
    run history_new_fails "$prev"
    [ "$output" = "brand new" ]
}

@test "history_latest() returns the newest run" {
    d="$HIST/$(hostname -s)"; mkdir -p "$d"
    touch "$d/20200101T000000Z.json" "$d/20250101T000000Z.json"
    [ "$(history_latest "$HIST")" = "$d/20250101T000000Z.json" ]
}

@test "generate_dashboard() embeds valid run data" {
    section "SSH"; fail "x </script> y"; ok "fine"
    history_save "$HIST" >/dev/null
    history_save "$HIST" >/dev/null
    generate_dashboard "$HIST" "$HIST/index.html"
    run python3 -c "
import re, json
s = open('$HIST/index.html').read()
assert s.count('</script>') == 1
d = json.loads(re.search(r'const RUNS = (.*?);\nconst STALE', s, re.S).group(1))
assert len(d) == 2 and d[-1]['findings'][0]['level'] == 'FAIL'
assert all(f['level'] != 'OK' for f in d[-1]['findings'])
"
    [ "$status" -eq 0 ]
}

@test "history_save() does not overwrite a run from the same second" {
    section "SSH"; fail "x"
    a=$(history_save "$HIST"); b=$(history_save "$HIST"); c=$(history_save "$HIST")
    [ "$a" != "$b" ] && [ "$b" != "$c" ] && [ "$a" != "$c" ]
    [ -f "$a" ] && [ -f "$b" ] && [ -f "$c" ]
}
