#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
# lib/report_txt.sh — Generate plain text audit report (audit trail)

generate_txt_report() {
    local output_file=$1

    local fails warns oks
    fails=$(grep -c "^FAIL	" "$FINDINGS_FILE" 2>/dev/null) || fails=0
    warns=$(grep -c "^WARN	" "$FINDINGS_FILE" 2>/dev/null) || warns=0
    oks=$(grep -c   "^OK	"   "$FINDINGS_FILE" 2>/dev/null) || oks=0
    local score; score=$(_overall_score)

    {
        echo "============================================================"
        echo "  ANZEN (安全) — Linux Security Audit Report"
        echo "  Anzen ${ANZEN_VERSION:-}"
        echo "============================================================"
        echo ""
        echo "  Hostname   : $(_hostname)"
        echo "  OS         : $OS_PRETTY"
        echo "  Kernel     : $(uname -r)"
        echo "  Public IP  : ${ANZEN_PUBLIC_IP:-unavailable}"
        echo "  Audited by : $(whoami)"
        echo "  Date       : $(date)"
        echo ""
        echo "============================================================"
        printf "  SUMMARY:  FAIL=%-3s  WARN=%-3s  OK=%-3s  SCORE=%s%%\n" \
            "$fails" "$warns" "$oks" "$score"
        echo "============================================================"
        echo ""
        echo "  Section scores:"
        local s f w _o sc
        while IFS=$'\t' read -r s f w _o sc; do
            printf "    %-36s %3s%%  FAIL=%-3s WARN=%s\n" "$s" "$sc" "$f" "$w"
        done < <(_section_scores)
        echo ""

        local cur_section=""
        while IFS=$'\t' read -r level sec msg id remedy; do
            if [ "$sec" != "$cur_section" ]; then
                echo ""
                echo "--- $sec ---"
                cur_section="$sec"
            fi
            printf "  [%-4s] %s\n" "$level" "$msg"
            [ "$level" != "OK" ] && printf "         ID:  %s\n" "$id"
            [ -n "$remedy" ] && [ "$level" != "OK" ] && [ "$level" != "INFO" ] && \
                printf "         Fix: %s\n" "$remedy"
        done < "$FINDINGS_FILE"

        echo ""
        echo "============================================================"
        echo "  END OF REPORT — $(date)"
        echo "============================================================"
    } > "$output_file"
}
