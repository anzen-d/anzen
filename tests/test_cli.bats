#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# tests/test_cli.bats — Tests for anzen.sh argument handling and module wiring

setup() {
    ANZEN_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    OUT_DIR="$(mktemp -d)"
}

teardown() {
    rm -rf "$OUT_DIR"
}

@test "--version matches latest CHANGELOG entry" {
    run "$ANZEN_DIR/anzen.sh" --version
    [ "$status" -eq 0 ]
    latest=$(grep -m1 -oE '^## \[[0-9.]+\]' "$ANZEN_DIR/CHANGELOG.md" | tr -d '#[] ')
    [ "$output" = "anzen $latest" ]
}

@test "unknown --check module is rejected" {
    run "$ANZEN_DIR/anzen.sh" --check=nosuchmodule
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unknown module: nosuchmodule"* ]]
}

@test "every lib/checks module is listed in ALL_MODULES" {
    mods=$(sed -n '/^ALL_MODULES=(/,/)/p' "$ANZEN_DIR/anzen.sh")
    for f in "$ANZEN_DIR"/lib/checks/*.sh; do
        name=$(basename "$f" .sh)
        [[ "$mods" == *"$name"* ]] || { echo "missing: $name"; return 1; }
    done
}

@test "every TUI module is listed in ALL_MODULES" {
    mods=$(sed -n '/^ALL_MODULES=(/,/)/p' "$ANZEN_DIR/anzen.sh")
    for name in $(sed -n '/^ALL_MODULES=(/,/^)/p' "$ANZEN_DIR/anzen-tui.sh" | grep -oE '^    [a-z_0-9]+ +"' | awk '{print $1}'); do
        [[ "$mods" == *"$name"* ]] || { echo "missing: $name"; return 1; }
    done
}

@test "--output= with several formats writes one file per extension" {
    run "$ANZEN_DIR/anzen.sh" --check=path_check --quiet --no-color --txt --json --output="$OUT_DIR/out.html"
    [ -f "$OUT_DIR/out.txt" ]
    [ -f "$OUT_DIR/out.json" ]
}

@test "--output= with one format uses the path as-is" {
    run "$ANZEN_DIR/anzen.sh" --check=path_check --quiet --no-color --json --output="$OUT_DIR/report.data"
    [ -f "$OUT_DIR/report.data" ]
}

@test "custom checks from CUSTOM_CHECKS_DIR run as modules" {
    mkdir -p "$OUT_DIR/cc"
    printf 'run_site_x_check() { section "Site X"; fail "site x broken"; }\n' > "$OUT_DIR/cc/site_x.sh"
    printf 'CUSTOM_CHECKS_DIR=%s\n' "$OUT_DIR/cc" > "$OUT_DIR/c.conf"
    chmod 600 "$OUT_DIR/c.conf"
    run "$ANZEN_DIR/anzen.sh" --config="$OUT_DIR/c.conf" --check=site_x --no-color
    [ "$status" -eq 1 ]
    [[ "$output" == *"site x broken"* ]]
}

@test "world-writable custom check is refused" {
    mkdir -p "$OUT_DIR/cc"
    printf 'run_evil_check() { fail "should not run"; }\n' > "$OUT_DIR/cc/evil.sh"
    chmod 666 "$OUT_DIR/cc/evil.sh"
    printf 'CUSTOM_CHECKS_DIR=%s\n' "$OUT_DIR/cc" > "$OUT_DIR/c.conf"
    chmod 600 "$OUT_DIR/c.conf"
    run "$ANZEN_DIR/anzen.sh" --config="$OUT_DIR/c.conf" --check=evil --no-color
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unknown module: evil"* ]]
    [[ "$output" != *"should not run"* ]]
}

@test "--dashboard without a history dir fails" {
    run "$ANZEN_DIR/anzen.sh" --dashboard="$OUT_DIR/d.html"
    [ "$status" -eq 1 ]
}

@test "files: world-readable shadow is FAIL, stricter-than-expected is OK" {
    run bash -c '
        source "'"$ANZEN_DIR"'/lib/output.sh"; FINDINGS_FILE=$(mktemp); QUIET=true
        source "'"$ANZEN_DIR"'/lib/checks/files.sh"
        d=$(mktemp -d); touch $d/s1 $d/s2 $d/s3
        chmod 644 $d/s1; chmod 000 $d/s2; chmod 650 $d/s3
        eval "$(sed -n "/_check_perm() {/,/^    }/p" "'"$ANZEN_DIR"'/lib/checks/files.sh")"
        _check_perm $d/s1 640; _check_perm $d/s2 640; _check_perm $d/s3 640
        cut -f1 "$FINDINGS_FILE" | tr "\n" " "'
    [[ "$output" == *"FAIL OK WARN"* ]]
}

@test "JSON report lists module durations and stays valid" {
    run "$ANZEN_DIR/anzen.sh" --check=path_check --check=kernel --quiet --no-color --json --output="$OUT_DIR/r.json"
    grep -qE '^  "durations": \{"path_check": [0-9]+, "kernel": [0-9]+\},$' "$OUT_DIR/r.json"
    python3 -m json.tool "$OUT_DIR/r.json" >/dev/null
}

@test "--debug writes a private trace with file:line, never to stderr" {
    # Read-only reports dir (as after a sudo run): falls back to a temp file
    cp -r "$ANZEN_DIR" "$OUT_DIR/a" && rm -rf "$OUT_DIR/a/reports" && mkdir "$OUT_DIR/a/reports" && chmod 555 "$OUT_DIR/a/reports"
    run bash -c "'$OUT_DIR/a/anzen.sh' --check=path_check --debug --no-color 2>&1 >/dev/null"
    log=$(sed -n 's/^Debug trace: //p' <<< "$output")
    [ -f "$log" ]
    [ "$(stat -c %a "$log")" = 600 ]
    grep -q '^+ path_check.sh:[0-9]* run_path_check_check: ' "$log"
    [ "$(grep -c '^+' <<< "$output")" -eq 0 ]
    rm -f "$log"
}

@test "--check run is not saved to HISTORY_DIR unless --history= is given" {
    printf 'HISTORY_DIR=%s/hist\n' "$OUT_DIR" > "$OUT_DIR/c.conf"; chmod 600 "$OUT_DIR/c.conf"
    run "$ANZEN_DIR/anzen.sh" --config="$OUT_DIR/c.conf" --check=path_check --no-color
    [[ "$output" == *"Partial run (--check): not saved to history"* ]]
    [ ! -d "$OUT_DIR/hist" ] || [ -z "$(ls -A "$OUT_DIR/hist")" ]
    run "$ANZEN_DIR/anzen.sh" --config="$OUT_DIR/c.conf" --history="$OUT_DIR/hist" --check=path_check --no-color
    [ "$(ls "$OUT_DIR"/hist/*/*.json | wc -l)" -eq 1 ]
}

@test "--offline makes no public-IP lookup" {
    run "$ANZEN_DIR/anzen.sh" --check=system --offline --no-color --json --output="$OUT_DIR/o.json"
    grep -q '"public_ip": "unavailable (--offline)"' "$OUT_DIR/o.json"
}
