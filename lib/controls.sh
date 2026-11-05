#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/controls.sh — map findings to NIST SP 800-53 / CIS Controls references
# (lib/data/controls.tsv). Bash 3.2 safe: the macOS edition uses it too.

# _findings_controls — one line per line of FINDINGS_FILE: the controls of the
# first matching mapping, or an empty line. Read it next to the findings on
# another file descriptor; the findings TSV itself stays unchanged.
_findings_controls() {
    local map="${ANZEN_CONTROLS_FILE:-${ANZEN_DIR:-${ROOT_DIR:-.}}/lib/data/controls.tsv}"
    if [ ! -f "$map" ]; then awk '{ print "" }' "$FINDINGS_FILE"; return 0; fi
    awk -F'\t' '
        NR == FNR {
            if ($0 ~ /^[[:space:]]*(#|$)/ || NF < 3) next
            n++; sre[n] = "^(" tolower($1) ")$"; mre[n] = tolower($2); ctl[n] = $3; next
        }
        {
            s = tolower($2); m = tolower($3); out = ""
            for (i = 1; i <= n; i++) if (s ~ sre[i] && m ~ mre[i]) { out = ctl[i]; break }
            print out
        }' "$map" "$FINDINGS_FILE"
}
