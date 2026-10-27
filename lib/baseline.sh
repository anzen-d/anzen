#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/baseline.sh — Baseline management and regression detection

BASELINE_FILE="${REPORT_DIR:-${ANZEN_DIR}/reports}/.baseline.json"

save_baseline() {
    local output="${1:-$BASELINE_FILE}"
    local dir; dir="$(dirname "$output")"
    mkdir -p "$dir"
    # Refuse to write through any symlink in the path
    if [ -L "$dir" ] || [ -L "$output" ]; then
        echo "ERROR: Baseline path '$output' involves a symlink — refusing to write" >&2
        return 1
    fi

    # Minimal JSON of the FAIL findings, one per line so _baseline_entries can
    # read it back with sed — no report_json or python3 dependency
    local date_str; date_str=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local fail_count; fail_count=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || fail_count=0

    {
        printf '{\n  "date": "%s",\n  "fails": [\n' "$date_str"
        local first=true level _sec msg id _remedy
        while IFS=$'\t' read -r level _sec msg id _remedy; do
            [ "$level" = "FAIL" ] || continue
            # Escape JSON special characters
            msg=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g')
            $first || printf ',\n'
            printf '    {"id": "%s", "message": "%s"}' "$id" "$msg"
            first=false
        done < "$FINDINGS_FILE"
        printf '\n  ],\n  "fail_count": %d\n}\n' "$fail_count"
    } > "$output"

    echo -e "\033[32m  Baseline saved: $output ($fail_count FAILs)\033[0m"
}

# _baseline_entries FILE — "ID<TAB>MESSAGE" per baseline FAIL. Baselines saved
# before 0.5.0 hold bare message strings; those come out with an empty ID
_baseline_entries() {
    sed -n '/"fails": \[/,/^  \]/p' "$1" | sed -n \
        -e 's/^    {"id": "\([^"]*\)", "message": "\(.*\)"},\{0,1\}$/\1\t\2/p' \
        -e 's/^    "\(.*\)",\{0,1\}$/\t\1/p' \
        | sed 's/\\"/"/g; s/\\\\/\\/g'
}

diff_baseline() {
    local baseline="${1:-$BASELINE_FILE}"

    if [ ! -f "$baseline" ]; then
        echo -e "\033[31m  No baseline found at $baseline\033[0m"
        echo -e "  Run with --baseline first to save a reference point."
        return 1
    fi

    local baseline_entries current_entries
    baseline_entries=$(_baseline_entries "$baseline")
    current_entries=$(awk -F'\t' '$1 == "FAIL" { print $4 "\t" $3 }' "$FINDINGS_FILE")

    # Compare by finding ID; an old message-only baseline falls back to messages
    local key=1
    if [ -n "$baseline_entries" ] && grep -q $'^\t' <<< "$baseline_entries"; then
        key=2
        echo -e "\033[33m  Baseline predates finding IDs — comparing messages; re-run --baseline\033[0m"
    fi

    # _only_in A B — messages of entries in A whose key is not in B
    _only_in() {
        awk -F'\t' -v k="$key" 'NR == FNR { if ($0 != "") seen[$k] = 1; next }
                                $0 != "" && !($k in seen) { print $2 }' \
            <(printf '%s\n' "$2") <(printf '%s\n' "$1") | sort -u
    }

    local new_fails resolved_fails
    new_fails=$(_only_in "$current_entries" "$baseline_entries")
    resolved_fails=$(_only_in "$baseline_entries" "$current_entries")

    echo -e "\n\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[1m  BASELINE DIFF\033[0m  (vs $(stat -c "%y" "$baseline" 2>/dev/null | cut -d. -f1))"
    echo -e "\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

    if [ -n "$new_fails" ]; then
        echo -e "\033[1m\033[31m  NEW FAILURES (regressions):\033[0m"
        while IFS= read -r f; do
            echo -e "  \033[31m+ $f\033[0m"
        done <<< "$new_fails"
    fi

    if [ -n "$resolved_fails" ]; then
        echo -e "\033[1m\033[32m  RESOLVED (fixed since baseline):\033[0m"
        while IFS= read -r f; do
            echo -e "  \033[32m- $f\033[0m"
        done <<< "$resolved_fails"
    fi

    if [ -z "$new_fails" ] && [ -z "$resolved_fails" ]; then
        echo -e "\033[32m  No changes since baseline.\033[0m"
    fi

    # Return 1 if regressions exist
    [ -z "$new_fails" ]
}
