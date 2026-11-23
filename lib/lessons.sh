#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/lessons.sh — attach a short lesson to a finding (lib/data/lessons.tsv).
# Bash 3.2 safe: the macOS edition reads the same report code.

# _findings_lessons — one line per line of FINDINGS_FILE: the lesson of the
# first matching line as TITLE<TAB>WHY<TAB>BEFORE_YOU_CHANGE<TAB>VERIFY, or an
# empty line. Read it next to the findings on another file descriptor.
_findings_lessons() {
    _findings_map "${ANZEN_LESSONS_FILE:-${ANZEN_DIR:-${ROOT_DIR:-.}}/lib/data/lessons.tsv}" 6
}

# _lessons_js — lessons.tsv as a JavaScript array literal for the dashboard,
# one [SECTION_REGEX, MESSAGE_REGEX, TITLE, WHY, BEFORE_YOU_CHANGE, VERIFY] per
# lesson. The page matches them itself: fleet reports carry no lessons
_lessons_js() {
    local map="${ANZEN_LESSONS_FILE:-${ANZEN_DIR:-${ROOT_DIR:-.}}/lib/data/lessons.tsv}" js
    [ -f "$map" ] || { printf '[]'; return 0; }
    js=$(awk -F'\t' '
        function esc(v) { gsub(/\\/, "&&", v); gsub(/"/, "\\\"", v); gsub(/[\001-\037]/, "", v); return v }
        /^[[:space:]]*(#|$)/ || NF < 6 { next }
        { printf "%s[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]", (n++ ? ",\n" : ""), esc($1), esc($2), esc($3), esc($4), esc($5), esc($6) }' "$map")
    # "</script>" in a lesson must not end the page's script block
    printf '[%s]' "${js//<\//<\\/}"
}

# lesson_explain ID JSON_REPORT — the finding with that ID from a JSON report
# as plain text: message, fix, control references and its lesson. Returns 1
# when the report has no such finding
lesson_explain() {
    local id=$1 tsv level sec msg remedy ctl les l_title l_why l_risk l_verify rc=0
    tsv=$(umask 077; mktemp)
    # The one-finding-per-line layout of report_json.sh; the ID is plain text
    S='"([^"\\]|\\.)*"' awk -v id="$id" '
        BEGIN { S = ENVIRON["S"]; pre = "    {\"id\": \"" id "\", \"level\": " }
        function str(   v) {
            if (!match(rest, S)) return ""
            v = substr(rest, RSTART + 1, RLENGTH - 2); rest = substr(rest, RSTART + RLENGTH)
            gsub(/\\"/, "\"", v); gsub(/\\\\/, "\\", v)
            return v
        }
        index($0, pre) == 1 {
            rest = substr($0, length(pre) + 1)
            lvl = str(); str(); sec = str(); str(); msg = str(); str(); fix = str()
            printf "%s\t%s\t%s\t%s\t%s\n", lvl, sec, msg, id, fix
            exit
        }' "$2" > "$tsv"
    if IFS=$'\t' read -r level sec msg _ remedy < "$tsv" && [ -n "$level" ]; then
        ctl=$(FINDINGS_FILE=$tsv _findings_controls)
        les=$(FINDINGS_FILE=$tsv _findings_lessons)
        printf '[%s] %s\n%s\nID: %s\n' "$level" "$sec" "$msg" "$id"
        [ -n "$remedy" ] && printf '\nFix:\n  %s\n' "$remedy"
        [ -n "$ctl" ] && printf '\nRef: %s\n' "$ctl"
        if [ -n "$les" ]; then
            IFS=$'\t' read -r l_title l_why l_risk l_verify <<< "$les"
            printf '\n%s\n\nWhy it matters\n%s\n\nBefore you change it\n%s\n\nCheck that it worked\n  %s\n' \
                "$l_title" "$(fold -s -w 76 <<< "$l_why" | sed 's/^/  /')" \
                "$(fold -s -w 76 <<< "$l_risk" | sed 's/^/  /')" "$l_verify"
        else
            printf '\nNo lesson for this finding yet.\n'
        fi
    else
        rc=1
    fi
    rm -f "$tsv"
    return "$rc"
}
