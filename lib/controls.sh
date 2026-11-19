#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/controls.sh — map findings to NIST SP 800-53 / CIS Controls references
# (lib/data/controls.tsv). Bash 3.2 safe: the macOS edition uses it too.

# _findings_controls — one line per line of FINDINGS_FILE: the controls of the
# first matching mapping, or an empty line. Read it next to the findings on
# another file descriptor; the findings TSV itself stays unchanged.
_findings_controls() {
    _findings_map "${ANZEN_CONTROLS_FILE:-${ANZEN_DIR:-${ROOT_DIR:-.}}/lib/data/controls.tsv}" 3
}

# _findings_map MAP_FILE FIELDS — the shared matcher behind controls.tsv and
# lessons.tsv. A map line is SECTION_REGEX<TAB>MESSAGE_REGEX<TAB>value...; a
# line with fewer than FIELDS fields is ignored. Prints fields 3..FIELDS of the
# first matching line, tab-separated.
_findings_map() {
    local map=$1
    if [ ! -f "$map" ]; then awk '{ print "" }' "$FINDINGS_FILE"; return 0; fi
    awk -F'\t' -v nf="$2" '
        NR == FNR {
            if ($0 ~ /^[[:space:]]*(#|$)/ || NF < nf) next
            n++; sre[n] = "^(" tolower($1) ")$"; mre[n] = tolower($2)
            val[n] = $3; for (j = 4; j <= nf; j++) val[n] = val[n] "\t" $j
            next
        }
        {
            s = tolower($2); m = tolower($3); out = ""
            for (i = 1; i <= n; i++) if (s ~ sre[i] && m ~ mre[i]) { out = val[i]; break }
            print out
        }' "$map" "$FINDINGS_FILE"
}
