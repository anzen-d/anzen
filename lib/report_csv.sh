#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/report_csv.sh — findings as CSV (RFC 4180) for spreadsheets and ticket
# imports. Bash 3.2 safe: the macOS edition uses it too.

# generate_csv_report FILE — host,date,level,section,id,message,remedy,controls
generate_csv_report() {
    local out=$1 host date
    host=$(_hostname); date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    {
        printf 'host,date,level,section,id,message,remedy,controls\r\n'
        paste -d'\t' "$FINDINGS_FILE" <(_findings_controls | sed 's/^/\t/') \
        | awk -F'\t' -v host="$host" -v date="$date" '
            # Quote every field; a leading = + - @ would run as a formula in
            # spreadsheets (CSV injection), so it gets a leading apostrophe
            function q(v) { if (v ~ /^[=+@-]/) v = "'\''" v; gsub(/"/, "\"\"", v); return "\"" v "\"" }
            { printf "%s,%s,%s,%s,%s,%s,%s,%s\r\n", q(host), q(date), q($1), q($2), q($4), q($3), q($5), q($7) }'
    } > "$out"
}
