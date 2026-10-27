#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/report_json.sh — Generate machine-readable JSON report

_json_escape() {
    sed 's/\\/\\\\/g; s/"/\\"/g; s/'"$(printf '\t')"'/\\t/g; s/'"$(printf '\r')"'//g' <<< "$1"
}

generate_json_report() {
    local output_file=$1

    local fails warns oks infos
    fails=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || fails=0
    warns=$(grep -c "^WARN	" "$FINDINGS_FILE" 2>/dev/null) || warns=0
    oks=$(grep -c   "^OK	"   "$FINDINGS_FILE" 2>/dev/null) || oks=0
    infos=$(grep -c "^INFO	" "$FINDINGS_FILE" 2>/dev/null) || infos=0

    local score; score=$(_overall_score)

    {
        printf '{\n'
        printf '  "hostname": "%s",\n'   "$(_json_escape "$(_hostname)")"
        printf '  "os": "%s",\n'         "$(_json_escape "$OS_PRETTY")"
        printf '  "kernel": "%s",\n'     "$(_json_escape "$(uname -r)")"
        printf '  "arch": "%s",\n'       "$(_json_escape "$(uname -m)")"
        printf '  "public_ip": "%s",\n'  "$(_json_escape "${ANZEN_PUBLIC_IP:-}")"
        printf '  "audited_by": "%s",\n' "$(_json_escape "$(whoami)")"
        printf '  "version": "%s",\n'    "${ANZEN_VERSION:-}"
        printf '  "date": "%s",\n'       "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        printf '  "summary": {"fail": %d, "warn": %d, "ok": %d, "info": %d, "score": %d},\n' \
            "$fails" "$warns" "$oks" "$infos" "$score"
        printf '  "sections": ['
        local s f w o sc sfirst=true
        while IFS=$'\t' read -r s f w o sc; do
            $sfirst || printf ','
            sfirst=false
            printf '\n    {"name": "%s", "fail": %d, "warn": %d, "ok": %d, "score": %d}' \
                "$(_json_escape "$s")" "$f" "$w" "$o" "$sc"
        done < <(_section_scores)
        printf '\n  ],\n'
        printf '  "findings": [\n'

        # One awk pass instead of a sed per field: large hosts have 400+ findings
        awk -F'\t' '
            function esc(v) {
                gsub(/\\/, "&&", v); gsub(/"/, "\\\"", v); gsub(/\r/, "", v)
                return v
            }
            {
                if (NR > 1) printf ",\n"
                printf "    {\"id\": \"%s\", \"level\": \"%s\", \"section\": \"%s\", \"message\": \"%s\", \"remedy\": \"%s\"}", \
                    esc($4), esc($1), esc($2), esc($3), esc($5)
            }' "$FINDINGS_FILE"

        printf '\n  ]\n}\n'
    } > "$output_file"
}
