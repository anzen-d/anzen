#!/usr/bin/env bats
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
